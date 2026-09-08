"""Kindle Bluetooth Audio Pipeline & Dynamic Resampling Engine.

Provides real-time PCM resampling (supporting 16kHz Piper TTS, 22.05kHz KOReader,
44.1kHz, 48kHz mono/stereo -> 44.1kHz stereo S16_LE) and SBC RTP frame generation
for A2DP Bluetooth streaming on Kindle ARMv7 hardware.
"""

import array
import audioop
import ctypes
import fcntl
import logging
import os
import threading
from collections import deque

log = logging.getLogger(__name__)

SBC_BITPOOL_DEFAULT = 35
PCM_BYTES_PER_SAMPLE = 4
SAMPLES_PER_FRAME = 16 * 8
FRAMES_PER_PACKET = 5
PCM_FRAME_SIZE = SAMPLES_PER_FRAME * PCM_BYTES_PER_SAMPLE
PCM_PACKET_SIZE = PCM_FRAME_SIZE * FRAMES_PER_PACKET

# Buffer target: 8 packets (~116 ms of audio) to absorb jitter without latency lag
MAX_BUFFERED_PACKETS = 8
BUFFER_TARGET = PCM_PACKET_SIZE * MAX_BUFFERED_PACKETS
READ_CHUNK_MAX = 8192

# F_SETPIPE_SZ: limit kernel pipe size to reduce accumulated latency
F_SETPIPE_SZ = 1031
FIFO_PIPE_SIZE = 16384

# Shared with assets/audio-hack/gst-launch-wrapper.sh, which writes to the FIFO
# and publishes the caps it saw to the sidecar. Keep the two in step.
MIN_INPUT_RATE = 4000
MAX_INPUT_RATE = 192000

FIFO_PATH = "/tmp/kindle_audio.fifo"
FMT_PATH = "/tmp/kindle_audio.fmt"


class AudioResampler:
    """Dynamic PCM Resampler supporting 16kHz, 22.05kHz, 44.1kHz, 48kHz mono/stereo
    resampling to 44.1kHz stereo S16_LE with minimal CPU overhead (<1%) on ARMv7.
    """

    def __init__(
        self,
        in_rate: int = 22050,
        in_channels: int = 1,
        out_rate: int = 44100,
        out_channels: int = 2,
        fmt_path: str = FMT_PATH,
    ):
        self.in_rate = in_rate
        self.in_channels = in_channels
        self.out_rate = out_rate
        self.out_channels = out_channels
        self.fmt_path = fmt_path
        self._rate_state = None
        self._odd_byte = b""
        self._fmt_mtime = 0

    def check_format_update(self):
        """Adopt the format the wrapper published, if it published a new one.

        A rewritten sidecar means a new pipeline, which is the only stream
        boundary visible from here: the FIFO is held open read-write, so a
        writer going away never surfaces as end-of-file. Treat it as one and
        drop the carried state, or a partial sample left by a pipeline that
        was killed mid-write shifts every following sample by a byte.
        """
        try:
            st = os.stat(self.fmt_path)
        except OSError:
            return  # No sidecar yet; keep the format we are already using.
        if st.st_mtime == self._fmt_mtime:
            return

        try:
            with open(self.fmt_path, "r") as f:
                content = f.read()
            new_rate = None
            new_channels = None
            for token in content.split():
                if token.startswith("rate="):
                    new_rate = int(token.split("=")[1])
                elif token.startswith("channels="):
                    new_channels = int(token.split("=")[1])
        except (OSError, ValueError) as e:
            # Leave _fmt_mtime alone so a readable rewrite is picked up later.
            log.warning(f"[AudioResampler] Ignoring unreadable {self.fmt_path}: {e}")
            return

        self._fmt_mtime = st.st_mtime
        self.new_stream()
        self.set_format(new_rate, new_channels)

    def new_stream(self):
        """Forget state carried from the previous writer."""
        self._rate_state = None
        self._odd_byte = b""

    def set_format(self, in_rate: int = None, in_channels: int = None):
        """Update input audio sample rate and channel configuration."""
        changed = False
        if in_rate and MIN_INPUT_RATE <= in_rate <= MAX_INPUT_RATE and in_rate != self.in_rate:
            self.in_rate = in_rate
            changed = True
        elif in_rate and not (MIN_INPUT_RATE <= in_rate <= MAX_INPUT_RATE):
            # A rate outside audio range is a parse artefact, not a stream.
            # Resampling from it allocates in proportion to in_rate/out_rate.
            log.warning(f"[AudioResampler] Ignoring out-of-range rate {in_rate}Hz")
        if in_channels and in_channels in (1, 2) and in_channels != self.in_channels:
            self.in_channels = in_channels
            changed = True
        if changed:
            self.new_stream()
            log.info(
                f"[AudioResampler] Format set: {self.in_rate}Hz {self.in_channels}ch -> "
                f"{self.out_rate}Hz {self.out_channels}ch"
            )

    def resample_chunk(self, chunk: bytes) -> bytes:
        """Resample a chunk of raw S16_LE PCM from (in_rate, in_channels) to (out_rate, out_channels)."""
        if not chunk and not self._odd_byte:
            return b""

        if self._odd_byte:
            chunk = self._odd_byte + chunk
            self._odd_byte = b""

        # Preserve sample frame alignment (2 bytes per sample * in_channels)
        frame_align = 2 * self.in_channels
        rem = len(chunk) % frame_align
        if rem:
            self._odd_byte = chunk[-rem:]
            chunk = chunk[:-rem]

        if not chunk:
            return b""

        # Fast path 1: 22050 Hz mono -> 44100 Hz stereo (KOReader Audiobook fast path)
        if self.in_rate == 22050 and self.in_channels == 1 and self.out_rate == 44100 and self.out_channels == 2:
            try:
                in_arr = array.array("h", chunk)
                out_arr = array.array("h", bytes(len(chunk) * 4))
                out_arr[0::4] = in_arr
                out_arr[1::4] = in_arr
                out_arr[2::4] = in_arr
                out_arr[3::4] = in_arr
                return out_arr.tobytes()
            except Exception as e:
                log.warning(f"[AudioResampler] Fast-path 22k mono error: {e}")

        # Fast path 2: 44100 Hz stereo -> 44100 Hz stereo (Identity)
        if self.in_rate == 44100 and self.in_channels == 2 and self.out_rate == 44100 and self.out_channels == 2:
            return chunk

        # Fast path 3: 44100 Hz mono -> 44100 Hz stereo
        if self.in_rate == 44100 and self.in_channels == 1 and self.out_rate == 44100 and self.out_channels == 2:
            try:
                return audioop.tostereo(chunk, 2, 1, 1)
            except Exception as e:
                log.warning(f"[AudioResampler] Fast-path 44k mono error: {e}")

        # General resampling path using audioop.ratecv
        try:
            if self.in_rate != self.out_rate:
                converted, self._rate_state = audioop.ratecv(
                    chunk, 2, self.in_channels, self.in_rate, self.out_rate, self._rate_state
                )
            else:
                converted = chunk

            if self.in_channels == 1 and self.out_channels == 2:
                converted = audioop.tostereo(converted, 2, 1, 1)
            elif self.in_channels == 2 and self.out_channels == 1:
                converted = audioop.tomono(converted, 2, 0.5, 0.5)

            return converted
        except Exception as e:
            log.warning(
                f"[AudioResampler] General resample error ({self.in_rate}Hz {self.in_channels}ch -> "
                f"{self.out_rate}Hz {self.out_channels}ch): {e}"
            )
            return b""

    def reset(self):
        """Reset internal filter states and buffers."""
        self._rate_state = None
        self._odd_byte = b""


class SbcStruct(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulong),
        ("frequency", ctypes.c_uint8),
        ("blocks", ctypes.c_uint8),
        ("subbands", ctypes.c_uint8),
        ("mode", ctypes.c_uint8),
        ("allocation", ctypes.c_uint8),
        ("bitpool", ctypes.c_uint8),
        ("endian", ctypes.c_uint8),
    ]


class SbcEncoder:
    def __init__(self, bitpool: int = SBC_BITPOOL_DEFAULT):
        self.bitpool = bitpool
        self._sbc_lib = None
        self._sbc_struct = None
        self._available = False
        self._init_libsbc()

    def _init_libsbc(self):
        try:
            try:
                self._sbc_lib = ctypes.CDLL("libsbc.so.1")
            except OSError:
                lib_name = os.path.join(os.path.dirname(__file__), "libsbc.so.1")
                if not os.path.exists(lib_name):
                    lib_name = "/mnt/us/kindle_hid_passthrough/libsbc.so.1"
                self._sbc_lib = ctypes.CDLL(lib_name)
            self._sbc_struct = ctypes.create_string_buffer(1024)
            self._sbc_lib.sbc_init.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
            self._sbc_lib.sbc_init.restype = ctypes.c_int

            self._sbc_lib.sbc_encode.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_ssize_t),
            ]
            self._sbc_lib.sbc_encode.restype = ctypes.c_ssize_t

            ret = self._sbc_lib.sbc_init(self._sbc_struct, 0)
            if ret == 0:
                sbc_cfg = ctypes.cast(self._sbc_struct, ctypes.POINTER(SbcStruct)).contents
                sbc_cfg.frequency = 0x02  # 44.1 kHz
                sbc_cfg.blocks = 0x03     # 16 blocks
                sbc_cfg.subbands = 0x01   # 8 subbands
                sbc_cfg.mode = 0x03       # Joint Stereo
                sbc_cfg.allocation = 0x00 # Loudness
                sbc_cfg.bitpool = self.bitpool
                self._available = True
                log.info("[Audio] libsbc loaded successfully")
        except Exception as e:
            log.warning(f"[Audio] libsbc initialization failed: {e}")
            self._available = False

    @property
    def is_available(self) -> bool:
        return self._available

    def encode_frame(self, pcm_chunk: bytes) -> bytes:
        if not self._available or len(pcm_chunk) < PCM_FRAME_SIZE:
            return None
        out_buf = ctypes.create_string_buffer(256)
        written = ctypes.c_ssize_t(0)
        res = self._sbc_lib.sbc_encode(
            self._sbc_struct, pcm_chunk, PCM_FRAME_SIZE, out_buf, 256, ctypes.byref(written)
        )
        if res > 0 and written.value > 0:
            return out_buf.raw[:written.value]
        return None

    def close(self):
        # sbc_finish frees the private state, so the encoder must be marked
        # unusable in the same breath: a later encode_frame would dereference
        # a freed pointer inside libsbc and take the process with it. close()
        # is reached twice on teardown (explicitly, then from the generator's
        # finally at GC), so it has to be idempotent.
        if self._available and self._sbc_lib:
            self._available = False
            try:
                self._sbc_lib.sbc_finish(self._sbc_struct)
            except Exception:
                # Teardown only; a failure here has nothing left to affect.
                pass


class FifoAudioStreamer:
    """Reads raw PCM of arbitrary rate/channel from FIFO, resamples to 44.1kHz stereo,
    and delivers ready RTP/SBC payloads for AVDTP streaming pump.

    Flow control: Consumer pulls in real-time (~14.5 ms per packet). This streamer
    maintains up to BUFFER_TARGET output bytes in memory and applies backpressure
    to the FIFO writer when full.
    """

    def __init__(self, fifo_path: str = FIFO_PATH):
        self.fifo_path = fifo_path
        self.fifo_fd = None
        self._chunks = deque()
        self._avail = 0
        self.resampler = AudioResampler()
        self.encoder = SbcEncoder()

        # An encoder that initialised but cannot produce a frame is unusable:
        # without a silence frame there is nothing to substitute when a later
        # encode fails, and joining None into the payload would kill the pump.
        self.silence_sbc_frame = self.encoder.encode_frame(b"\x00" * PCM_FRAME_SIZE)
        if self.silence_sbc_frame:
            self.silence_rtp_payload = (
                bytes([FRAMES_PER_PACKET]) + self.silence_sbc_frame * FRAMES_PER_PACKET
            )
        else:
            log.warning("[Audio] encoder produced no silence frame; streaming silence only")
            self.encoder.close()
            self.silence_rtp_payload = bytes([0])
        self._ensure_fifo()
        self.paused = False
        # toggle_pause is called from the API server's thread while the pump
        # reads self.paused on the event loop; the read-modify-write needs it.
        self._pause_lock = threading.Lock()

    def toggle_pause(self):
        with self._pause_lock:
            self.paused = not self.paused

    def play(self):
        self.paused = False

    def pause(self):
        self.paused = True

    # ---------- FIFO ----------

    def _ensure_fifo(self):
        try:
            if not os.path.exists(self.fifo_path):
                os.mkfifo(self.fifo_path, 0o666)
        except OSError:
            # Someone else may have created it between the check and the call.
            # If it is really unusable the open below reports it.
            pass

        try:
            self.fifo_fd = os.open(self.fifo_path, os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            log.warning(f"[Audio] cannot open {self.fifo_path}: {e}")
            self.fifo_fd = None
            return

        try:
            fcntl.fcntl(self.fifo_fd, F_SETPIPE_SZ, FIFO_PIPE_SIZE)
        except OSError:
            # Tuning, not a requirement: the default pipe size still works,
            # it just holds less before the writer blocks.
            pass

    # ---------- buffer O(1) ----------

    def _push(self, data: bytes):
        if data:
            self._chunks.append(data)
            self._avail += len(data)

    def _pull(self, n: int) -> bytes:
        if self._avail < n:
            return None
        out = bytearray(n)
        pos = 0
        while pos < n:
            head = self._chunks[0]
            need = n - pos
            if len(head) <= need:
                out[pos : pos + len(head)] = head
                pos += len(head)
                self._chunks.popleft()
            else:
                out[pos:n] = head[:need]
                self._chunks[0] = head[need:]
                pos = n
        self._avail -= n
        return bytes(out)

    # ---------- reading & dynamic resampling ----------

    def read_pcm_available(self):
        if self.fifo_fd is None:
            return
        self.resampler.check_format_update()
        while self._avail < BUFFER_TARGET:
            bytes_needed = BUFFER_TARGET - self._avail
            in_bps = self.resampler.in_rate * self.resampler.in_channels * 2
            out_bps = self.resampler.out_rate * self.resampler.out_channels * 2
            if out_bps > 0:
                approx_want = max(512, int(bytes_needed * in_bps / out_bps))
            else:
                approx_want = 1024
            want = min(READ_CHUNK_MAX, max(512, approx_want))
            frame_align = 2 * self.resampler.in_channels
            want = (want // frame_align) * frame_align
            if want < frame_align:
                want = frame_align

            try:
                chunk = os.read(self.fifo_fd, want)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            if not chunk:
                break
            resampled = self.resampler.resample_chunk(chunk)
            if resampled:
                self._push(resampled)
            elif chunk:
                # Nothing came back from a non-empty read: the format is wrong
                # or the resampler is failing. Looping would drain the whole
                # FIFO into the void, one warning per iteration.
                break
            if len(chunk) < want:
                break

    def get_next_payload(self) -> bytes:
        if self.paused:
            return self.silence_rtp_payload

        self.read_pcm_available()

        if (self._avail >= PCM_PACKET_SIZE and self.encoder.is_available
                and self.silence_sbc_frame):
            raw_packet_pcm = self._pull(PCM_PACKET_SIZE)
            sbc_frames = []
            for i in range(FRAMES_PER_PACKET):
                pcm_chunk = raw_packet_pcm[i * PCM_FRAME_SIZE : (i + 1) * PCM_FRAME_SIZE]
                encoded = self.encoder.encode_frame(pcm_chunk)
                sbc_frames.append(encoded if encoded else self.silence_sbc_frame)
            return bytes([FRAMES_PER_PACKET]) + b"".join(sbc_frames)

        return self.silence_rtp_payload

    def close(self):
        if self.fifo_fd is not None:
            try:
                os.close(self.fifo_fd)
            except OSError:
                # Closing an already-dead fd is not worth reporting.
                pass
            self.fifo_fd = None
        self._chunks.clear()
        self._avail = 0
        self.resampler.reset()
        self.encoder.close()
