"""Bounded fan-out using Wireshark filters and byte-preserving record copies.

Unsupported Lua builds or incomplete tap execution fall back to ordinary -Y
extraction. Python copies capture records, never interprets network headers.
"""

from pathlib import Path
import tempfile
import struct
from contextlib import ExitStack

from .pcap_metrics import classic_pcap_metrics
from .process import run_analysis_command, analysis_checkpoint
from .health import record_analysis_progress


def _lua_string(value):
    return '"' + "".join(f"\\{byte:03d}" for byte in str(value).encode("utf-8")) + '"'


def _records(source):
    """Yield (packet ordinal or None, original bytes), including metadata."""
    with open(source, "rb") as stream:
        magic = stream.read(4)
        stream.seek(0)
        ordinal = 0
        if magic != b'\x0a\x0d\x0d\x0a':
            header = stream.read(24)
            order = '<' if magic in {b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'} else '>'
            yield None, header
            while header := stream.read(16):
                analysis_checkpoint()
                if len(header) != 16:
                    raise ValueError("capture changed during dispatch")
                size = struct.unpack(order + 'IIII', header)[2]
                if size > 64 * 1024 * 1024:
                    raise ValueError("packet exceeds dispatch buffer limit")
                packet = stream.read(size)
                if len(packet) != size:
                    raise ValueError("capture changed during dispatch")
                ordinal += 1
                yield ordinal, header + packet
            return
        order = None
        while header := stream.read(12):
            analysis_checkpoint()
            if len(header) != 12:
                raise ValueError("capture changed during dispatch")
            if header[:4] == magic:
                order = '<' if header[8:12] == b'\x4d\x3c\x2b\x1a' else '>'
            if order is None:
                raise ValueError("missing capture section")
            kind, size = struct.unpack(order + 'II', header[:8])
            if size < 12 or size > 64 * 1024 * 1024 or size % 4:
                raise ValueError("invalid dispatch block size")
            rest = stream.read(size - 12)
            if len(rest) != size - 12:
                raise ValueError("capture changed during dispatch")
            if kind == 6:
                ordinal += 1
                yield ordinal, header + rest
            elif kind in {0x0A0D0D0A, 1, 4, 5}:
                yield None, header + rest
            else:
                raise ValueError("unsupported packet block")


def _dispatch(source, root, count):
    with ExitStack() as stack:
        indexes = [stack.enter_context((root / f'{index}.frames').open()) for index in range(count)]
        outputs = [stack.enter_context((root / f'{index}.pcapng').open('wb')) for index in range(count)]
        def next_number(index):
            line = indexes[index].readline()
            return int(line) if line else None
        wanted = [next_number(index) for index in range(count)]
        for ordinal, record in _records(source):
            if ordinal is None:
                for output in outputs:
                    output.write(record)
                continue
            if ordinal % 4096 == 0:
                record_analysis_progress("pcap.copy_packets", ordinal)
            for index, number in enumerate(wanted):
                if number is not None and number < ordinal:
                    raise ValueError("non-monotonic packet selection")
                if number == ordinal:
                    outputs[index].write(record)
                    wanted[index] = next_number(index)
        if any(number is not None for number in wanted):
            raise ValueError("packet selection exceeds input")


class BatchExtraction:
    MAX_FILTERS = 32

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="traffictracer-pcap-batch-")
        self.cache = {}
        return self

    def __exit__(self, *args):
        self.temp.cleanup()

    def prepare(self, source, filters):
        filters = sorted(set(filter(None, filters)))
        if len(filters) < 2:
            return
        # Do not run additional tools for missing/unsupported inputs. Existing
        # extraction remains the error and compatibility authority.
        try:
            if classic_pcap_metrics(Path(source)) is None:
                return
        except (OSError, ValueError):
            return
        for offset in range(0, len(filters), self.MAX_FILTERS):
            analysis_checkpoint()
            record_analysis_progress("pcap.batch_filters", offset, len(filters))
            group = filters[offset:offset + self.MAX_FILTERS]
            before = Path(source).stat()
            root = Path(tempfile.mkdtemp(dir=self.temp.name))
            script = root / "dispatch.lua"
            parts = ["local taps = {}"]
            for index, expression in enumerate(group):
                parts.append(f"""
do
 local tap = Listener.new('frame', {_lua_string(expression)})
 taps[#taps + 1] = tap
 local output = assert(io.open({_lua_string(root / f'{index}.frames')}, 'w'))
 local failed, finished = false, false
 local count = 0
 function tap.packet(pinfo)
  if finished then failed = true; return end
  local ok = pcall(function()
   assert(output:write(tostring(pinfo.number) .. '\\n'))
   count = count + 1
  end)
  if not ok then failed = true end
 end
 function tap.draw()
  local ok = pcall(function() assert(output:close()) end)
  if not ok then failed = true end
  if not failed and not finished then print('TT_BATCH:{index}:' .. count) end
  finished = true
 end
end
""")
            script.write_text("\n".join(parts), encoding="utf-8")
            try:
                result = run_analysis_command(
                    ["tshark", "-n", "-r", source, "-q", "-X", f"lua_script:{script}"],
                    capture_output=True, text=True, check=False,
                )
                lines = (result.stdout or "").splitlines()
                markers = {}
                for line in lines:
                    if line.startswith("TT_BATCH:"):
                        _, index, count = line.split(":")
                        if int(index) in markers:
                            raise ValueError("repeated batch completion")
                        markers[int(index)] = int(count)
                if result.returncode or len(markers) != len(group):
                    return
                _dispatch(source, root, len(group))
                after = Path(source).stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError("capture changed during batch extraction")
                validated = {}
                for index, expression in enumerate(group):
                    output = root / f"{index}.pcapng"
                    metrics = classic_pcap_metrics(output) if output.exists() else (0, 0)
                    if metrics is None or metrics[0] != markers[index]:
                        raise ValueError("incomplete batch packet output")
                    validated[(source, expression)] = (output, metrics)
                self.cache.update(validated)
            except (OSError, ValueError, KeyError):
                return
        record_analysis_progress("pcap.batch_filters", len(filters), len(filters))
