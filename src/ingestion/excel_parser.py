"""Excel parser for device inventory files."""

import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
import re


@dataclass
class DeviceInventory:
    """Represents a device from the inventory."""
    serial_no: int
    network_layer: str
    node: str
    router_type: str
    current_version: str
    image_version: str
    raw_data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExcelInventoryParser:
    """Parser for Excel inventory files without external dependencies."""

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self.shared_strings: List[str] = []
        self.sheets: Dict[str, List[Dict[str, Any]]] = {}

    def _load_shared_strings(self, zip_file: zipfile.ZipFile) -> None:
        """Load shared strings from Excel file."""
        if 'xl/sharedStrings.xml' not in zip_file.namelist():
            return

        ss_xml = zip_file.read('xl/sharedStrings.xml')
        ss_root = ET.fromstring(ss_xml)
        ns = {'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}

        for si in ss_root.findall('.//main:si', ns):
            text_parts = []
            for t in si.findall('.//main:t', ns):
                if t.text:
                    text_parts.append(t.text)
            self.shared_strings.append(''.join(text_parts))

    def _get_sheet_names(self, zip_file: zipfile.ZipFile) -> List[str]:
        """Get list of sheet names from workbook."""
        wb_xml = zip_file.read('xl/workbook.xml')
        wb_root = ET.fromstring(wb_xml)
        ns = {'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}

        sheets = []
        for sheet in wb_root.findall('.//main:sheet', ns):
            sheets.append(sheet.get('name'))
        return sheets

    def _parse_cell_ref(self, cell_ref: str) -> tuple:
        """Parse cell reference like 'A1' to (column, row)."""
        match = re.match(r'([A-Z]+)(\d+)', cell_ref)
        if match:
            col = match.group(1)
            row = int(match.group(2))
            return col, row
        return None, None

    def _col_to_index(self, col: str) -> int:
        """Convert column letter to index (A=0, B=1, etc.)."""
        result = 0
        for char in col:
            result = result * 26 + (ord(char) - ord('A') + 1)
        return result - 1

    def _parse_sheet(self, zip_file: zipfile.ZipFile, sheet_index: int) -> List[Dict[str, Any]]:
        """Parse a single sheet and return rows as dictionaries."""
        sheet_path = f'xl/worksheets/sheet{sheet_index + 1}.xml'
        if sheet_path not in zip_file.namelist():
            return []

        sheet_xml = zip_file.read(sheet_path)
        sheet_root = ET.fromstring(sheet_xml)
        ns = {'main': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}

        rows_data = []
        for row in sheet_root.findall('.//main:row', ns):
            row_data = {}
            for cell in row.findall('.//main:c', ns):
                cell_ref = cell.get('r')
                cell_type = cell.get('t')
                value_elem = cell.find('main:v', ns)

                if value_elem is not None and value_elem.text:
                    if cell_type == 's':  # Shared string
                        idx = int(value_elem.text)
                        value = self.shared_strings[idx] if idx < len(self.shared_strings) else ''
                    else:
                        value = value_elem.text
                    row_data[cell_ref] = value

            if row_data:
                rows_data.append(row_data)

        return rows_data

    def parse(self) -> Dict[str, List[Dict[str, Any]]]:
        """Parse the Excel file and return all sheets."""
        with zipfile.ZipFile(self.file_path, 'r') as z:
            self._load_shared_strings(z)
            sheet_names = self._get_sheet_names(z)

            for i, name in enumerate(sheet_names):
                self.sheets[name] = self._parse_sheet(z, i)

        return self.sheets

    def get_device_inventory(self, sheet_name: str = "Image Details") -> List[DeviceInventory]:
        """Extract device inventory from the specified sheet."""
        if not self.sheets:
            self.parse()

        if sheet_name not in self.sheets:
            available = list(self.sheets.keys())
            raise ValueError(f"Sheet '{sheet_name}' not found. Available: {available}")

        raw_data = self.sheets[sheet_name]
        devices = []

        # Find header row and column mappings
        header_row = None
        col_mapping = {}

        for row in raw_data:
            # Look for header indicators
            for cell_ref, value in row.items():
                if value and 'S. No' in str(value):
                    header_row = row
                    break
            if header_row:
                break

        if not header_row:
            # Try to use first row as header
            if raw_data:
                header_row = raw_data[0]

        # Build column mapping from header
        if header_row:
            for cell_ref, value in header_row.items():
                col, _ = self._parse_cell_ref(cell_ref)
                if col:
                    col_mapping[col] = str(value).strip().lower().replace('.', '').replace(' ', '_')

        # Parse data rows
        current_layer = ""
        current_node = ""

        for row in raw_data:
            if row == header_row:
                continue

            # Extract values by column
            row_values = {}
            for cell_ref, value in row.items():
                col, row_num = self._parse_cell_ref(cell_ref)
                if col and col in col_mapping:
                    row_values[col_mapping[col]] = str(value).strip() if value else ""

            # Skip if no serial number or not numeric
            s_no = row_values.get('s_no', '')
            if not s_no or not s_no.isdigit():
                continue

            # Handle merged cells (carry forward values)
            layer = row_values.get('network_layer', '')
            if layer:
                current_layer = layer
            else:
                layer = current_layer

            node = row_values.get('node', '')
            if node:
                current_node = node
            else:
                node = current_node

            device = DeviceInventory(
                serial_no=int(s_no),
                network_layer=layer,
                node=node,
                router_type=row_values.get('router', ''),
                current_version=row_values.get('current_version', ''),
                image_version=row_values.get('image_version', ''),
                raw_data=row
            )
            devices.append(device)

        return devices

    def get_all_versions(self) -> Dict[str, List[str]]:
        """Extract all unique versions grouped by router type."""
        devices = self.get_device_inventory()
        versions = {}

        for device in devices:
            router = device.router_type
            if router not in versions:
                versions[router] = set()

            # Parse version strings (may contain multiple versions separated by /)
            for v in device.current_version.split('/'):
                v = v.strip()
                if v:
                    versions[router].add(v)

        return {k: sorted(list(v)) for k, v in versions.items()}

    def get_affected_devices(self, product: str, version_pattern: str) -> List[DeviceInventory]:
        """Find devices matching a product and version pattern."""
        devices = self.get_device_inventory()
        affected = []

        pattern = re.compile(version_pattern, re.IGNORECASE)

        for device in devices:
            if product.lower() in device.router_type.lower():
                if pattern.search(device.current_version):
                    affected.append(device)

        return affected
