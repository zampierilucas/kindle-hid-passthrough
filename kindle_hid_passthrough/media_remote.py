#!/usr/bin/env python3
"""Phone media remote — A2DP sink + AVRCP target.

The Kindle shows up as a Bluetooth audio device (CoD: Audio+Rendering
service classes, Audio/Video major, Loudspeaker minor). Once a phone
connects, its volume keys arrive as AVRCP absolute-volume commands and
are turned into PageUp/PageDown presses on a virtual boot keyboard,
which the koplugin and kindle-button-mapper consume like any other
keyboard. The received volume is re-centered to mid-range after each
burst so both directions keep working, and the phone's initial volume
sync after connect is ignored.
"""

import asyncio

from bumble import a2dp, avc, avdtp, avrcp

from bt_setup import ensure_uhid
from config import normalize_addr
from logging_utils import log
from uhid_handler import Bus, UHIDDevice

__all__ = ['MediaRemote', 'MEDIA_REMOTE_COD']

MEDIA_REMOTE_COD = 0x240414

PAGE_UP = 0x4B
PAGE_DOWN = 0x4E

BOOT_KEYBOARD_DESCRIPTOR = bytes([
    0x05, 0x01,
    0x09, 0x06,
    0xA1, 0x01,
    0x05, 0x07,
    0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01,
    0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
    0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
    0xC0,
])

RECENTER_VOLUME = 0x40
RECENTER_DELAY = 0.5
SYNC_GRACE = 2.0
KEY_RELEASE_DELAY = 0.05


class _Delegate(avrcp.Delegate):
    def __init__(self, remote):
        super().__init__(supported_events=[avrcp.EventId.VOLUME_CHANGED])
        self.remote = remote
        self.volume = RECENTER_VOLUME
        self._also = None

    def chain_key_events_to(self, delegate):
        """Also hand passthrough keys to another delegate.

        The protocol holds one delegate, and both consumers need something
        from it: this one declares VOLUME_CHANGED and implements
        set_absolute_volume, the host's turns media keys into HID reports.
        Keeping this one and forwarding keys preserves both; wrapping them in
        a plain multiplexer lost supported_events and the volume override,
        which silently disabled page turns from the phone.
        """
        self._also = delegate if delegate is not self else None

    async def set_absolute_volume(self, volume: int) -> None:
        previous = self.volume
        self.volume = volume
        self.remote.on_volume(previous, volume)

    async def on_key_event(self, key, pressed, data) -> None:
        self.remote.on_passthrough(key, pressed)
        if self._also is not None:
            await self._also.on_key_event(key, pressed, data)


class MediaRemote:
    """One phone at a time; bumble's AVRCP protocol handles a single peer."""

    def __init__(self, on_change=None):
        self.connections = {}
        self.uhid = None
        self.delegate = _Delegate(self)
        self.avrcp = None
        self._on_change = on_change
        self._recenter_handle = None
        self._grace_until = 0.0

    def setup(self, device, listener=None, avrcp_protocol=None):
        """Register SDP records and profile listeners on the bumble device.

        Must run inside the event loop: avrcp.Protocol creates futures.
        """
        # update, not assignment: the host publishes the A2DP Source record
        # before calling this, and replacing the dict dropped it -- the Kindle
        # then advertised a sink and no source. Handles must not collide with
        # the host's 0x00010002 either.
        device.sdp_service_records.update({
            0x00010011: a2dp.make_audio_sink_service_sdp_records(0x00010011),
            0x00010012: avrcp.ControllerServiceSdpRecord(
                0x00010012).to_service_attributes(),
            0x00010013: avrcp.TargetServiceSdpRecord(
                0x00010013,
                supported_features=(avrcp.TargetFeatures.CATEGORY_1
                                    | avrcp.TargetFeatures.CATEGORY_2),
            ).to_service_attributes(),
        })
        if listener is None:
            listener = avdtp.Listener.for_device(device)
        listener.on(listener.EVENT_CONNECTION, self._on_avdtp_connection)

        if avrcp_protocol is None:
            self.avrcp = avrcp.Protocol(delegate=self.delegate)
            self.avrcp.listen(device)
        else:
            self.avrcp = avrcp_protocol
            self.delegate.chain_key_events_to(self.avrcp.delegate)
            self.avrcp.delegate = self.delegate

        log.info("[Media] Remote ready (A2DP sink + AVRCP target)")

    def adopt(self, connection):
        """Track an inbound phone connection; profiles serve it via L2CAP."""
        addr = normalize_addr(str(connection.peer_address))
        self.connections[addr] = connection
        self._grace_until = asyncio.get_event_loop().time() + SYNC_GRACE
        connection.on('disconnection',
                      lambda reason: self._on_disconnection(addr, reason))
        log.success(f"[Media] Phone connected: {addr}")
        self._ensure_uhid()
        self._notify_change()

    def state_list(self) -> list:
        return [{"address": addr, "protocol": "media", "name": None,
                 "hid_ready": self.uhid is not None}
                for addr in self.connections]

    def close(self):
        if self._recenter_handle:
            self._recenter_handle.cancel()
            self._recenter_handle = None
        if self.uhid:
            try:
                self.uhid.destroy()
            except Exception:
                pass
            self.uhid = None
        self.connections.clear()

    def on_volume(self, previous: int, volume: int):
        if asyncio.get_event_loop().time() < self._grace_until:
            self._schedule_recenter()
            return
        if volume > previous:
            log.info(f"[Media] Volume up ({previous} -> {volume}): page forward")
            self._press(PAGE_DOWN)
        elif volume < previous:
            log.info(f"[Media] Volume down ({previous} -> {volume}): page back")
            self._press(PAGE_UP)
        self._schedule_recenter()

    def on_passthrough(self, key, pressed: bool):
        op = avc.PassThroughFrame.OperationId
        usage = {op.VOLUME_UP: PAGE_DOWN, op.FORWARD: PAGE_DOWN,
                 op.VOLUME_DOWN: PAGE_UP, op.BACKWARD: PAGE_UP}.get(key)
        if usage is None or not pressed:
            log.debug(f"[Media] Passthrough {key} pressed={pressed}")
            return
        log.info(f"[Media] Passthrough {key.name}")
        self._press(usage)

    def _on_disconnection(self, addr: str, reason):
        self.connections.pop(addr, None)
        log.warning(f"[Media] Phone disconnected: {addr} (reason={reason})")
        if not self.connections:
            self.close()
        self._notify_change()

    def _notify_change(self):
        if self._on_change:
            try:
                self._on_change()
            except Exception:
                pass

    def _on_avdtp_connection(self, server):
        sbc = a2dp.SbcMediaCodecInformation
        server.add_sink(avdtp.MediaCodecCapabilities(
            media_type=avdtp.MediaType.AUDIO,
            media_codec_type=a2dp.CodecType.SBC,
            media_codec_information=sbc(
                sampling_frequency=(sbc.SamplingFrequency.SF_16000
                                    | sbc.SamplingFrequency.SF_32000
                                    | sbc.SamplingFrequency.SF_44100
                                    | sbc.SamplingFrequency.SF_48000),
                channel_mode=(sbc.ChannelMode.MONO
                              | sbc.ChannelMode.DUAL_CHANNEL
                              | sbc.ChannelMode.STEREO
                              | sbc.ChannelMode.JOINT_STEREO),
                block_length=(sbc.BlockLength.BL_4
                              | sbc.BlockLength.BL_8
                              | sbc.BlockLength.BL_12
                              | sbc.BlockLength.BL_16),
                subbands=sbc.Subbands.S_4 | sbc.Subbands.S_8,
                allocation_method=(sbc.AllocationMethod.SNR
                                   | sbc.AllocationMethod.LOUDNESS),
                minimum_bitpool_value=2,
                maximum_bitpool_value=53,
            ),
        ))
        log.info("[Media] AVDTP connection, sink endpoint registered "
                 "(audio is discarded)")

    def _ensure_uhid(self):
        if self.uhid:
            return
        if not ensure_uhid():
            log.error("[Media] uhid unavailable; phone keys will go nowhere")
            return
        try:
            self.uhid = UHIDDevice(
                name="Phone Media Remote",
                report_descriptor=BOOT_KEYBOARD_DESCRIPTOR,
                bus=Bus.BLUETOOTH,
            )
            log.success("[Media] Virtual keyboard created")
            asyncio.get_event_loop().call_later(
                0.5, lambda: self.uhid and self.uhid.discover_input_paths())
        except Exception as e:
            log.error(f"[Media] Failed to create virtual keyboard: {e}")

    def _press(self, usage: int):
        if not self.uhid:
            return
        try:
            self.uhid.send_input(bytes([0, 0, usage, 0, 0, 0, 0, 0]))
            asyncio.get_event_loop().call_later(
                KEY_RELEASE_DELAY, self._release)
        except Exception as e:
            log.warning(f"[Media] Key send failed: {e}")

    def _release(self):
        if not self.uhid:
            return
        try:
            self.uhid.send_input(bytes(8))
        except Exception as e:
            log.warning(f"[Media] Key release failed: {e}")

    def _schedule_recenter(self):
        if self._recenter_handle:
            self._recenter_handle.cancel()
        self._recenter_handle = asyncio.get_event_loop().call_later(
            RECENTER_DELAY, self._recenter)

    def _recenter(self):
        self._recenter_handle = None
        self.delegate.volume = RECENTER_VOLUME
        if not self.avrcp:
            return
        try:
            self.avrcp.notify_volume_changed(RECENTER_VOLUME)
        except Exception as e:
            log.debug(f"[Media] Recenter notify failed: {e}")
