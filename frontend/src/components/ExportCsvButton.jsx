import { rowsToCsv, downloadCsv, sanitizeCsvFilename } from "../lib/csv.js";

// Drop this next to any table: pass the column headers, the row objects, and
// (optionally) how to pull a cell value out of a row for a given column —
// defaults to `row[column]`, which covers most evidence shapes already keyed
// by their column label. Entirely client-side; nothing is sent to the server.
export default function ExportCsvButton({ columns, rows, getCell, filename, label }) {
  if (!columns?.length || !rows?.length) {
    return null;
  }

  const cell = getCell || ((row, column) => row[column]);

  const handleClick = () => {
    const csv = rowsToCsv(
      columns,
      rows.map((row) => columns.map((column) => cell(row, column))),
    );
    downloadCsv(sanitizeCsvFilename(filename), csv);
  };

  return (
    <button type="button" className="csv-export-button" onClick={handleClick}>
      {label || "Export CSV"}
    </button>
  );
}
