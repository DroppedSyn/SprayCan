export function parseFindingFileName(fileName) {
  const match = (fileName || "").match(/^(\d+)\.(.+)\.json$/i);
  const scanType = match ? match[2] : (fileName || "").replace(/\.json$/i, "");
  return {
    name: fileName,
    tenantId: "unknown",
    dateKey: "",
    scanType,
    isAggregate: scanType === "all_scans",
  };
}

export function normalizeFiles(files) {
  const normalized = (files || []).map((file) => {
    const parsed = parseFindingFileName(file.name || file);
    return {
      ...parsed,
      ...(typeof file === "object" ? file : {}),
      name: parsed.name,
      tenantId: file?.tenantId || parsed.tenantId,
      dateKey: file?.dateKey || parsed.dateKey,
      scanType: file?.scanType || parsed.scanType,
      isAggregate: typeof file?.isAggregate === "boolean" ? file.isAggregate : parsed.isAggregate,
      tenantName: file?.tenantName || "",
    };
  });

  return Array.from(new Map(normalized.map((file) => [file.name, file])).values());
}

export function formatFileLabel(fileName) {
  return fileName
    .replace(/\.json$/i, "")
    .replace(/^\d+\./, "")
    .replace(/^[^.]+\.\d{2}_\d{2}_\d{2}\./, "")
    .replace(/^Scan__/, "")
    .replace(/_/g, " ")
    .replace(/\./g, " / ");
}

export function formatScanType(scanType) {
  return (scanType || "")
    .replace(/^Scan__/, "")
    .replace(/_/g, " ")
    .replace(/\./g, " / ");
}

export function isModelScanType(scanType) {
  return (scanType || "").includes("Model_") || (scanType || "").includes("Model ");
}

export function formatFileKind(file) {
  if (isModelScanType(file.scanType)) {
    return "Model";
  }
  if (file.isAggregate) {
    return "Bundle O' Scans";
  }
  if ((file.scanType || "").includes("Find_T0_Groups")) {
    return "Privileged Groups";
  }
  if ((file.scanType || "").includes("Service_Principals")) {
    return "Risky Service Principals";
  }
  if ((file.scanType || "").includes("Dynamic_Groups")) {
    return "Dynamic Groups";
  }
  if ((file.scanType || "").includes("Dangling_app-reg")) {
    return "Dangling Redirects";
  }
  return "Scan Output";
}

export function fileKindClass(file) {
  if (isModelScanType(file.scanType)) {
    return "model";
  }
  if (file.isAggregate) {
    return "bundle";
  }
  if ((file.scanType || "").includes("Find_T0_Groups")) {
    return "high";
  }
  if ((file.scanType || "").includes("Service_Principals")) {
    return "medium";
  }
  if ((file.scanType || "").includes("Dynamic_Groups")) {
    return "low";
  }
  if ((file.scanType || "").includes("Dangling_app-reg")) {
    return "info";
  }
  return "neutral";
}

export function formatDateKey(dateKey) {
  const match = (dateKey || "").match(/^(\d{2})_(\d{2})_(\d{2})$/);
  if (!match) {
    return dateKey || "Unknown date";
  }
  const [, year, month, day] = match;
  return `20${year}-${month}-${day}`;
}

export function formatTenantLabel(tenantId) {
  return (tenantId || "tenant").split("-")[0];
}

export function getTenantAlias(files, tenantId) {
  return files.find((file) => file.tenantId === tenantId && file.tenantName)?.tenantName || "";
}

export function hasTenantId(tenantId) {
  return Boolean(tenantId && tenantId !== "unknown");
}

export function buildFileGroups(files) {
  const groups = new Map();

  files.forEach((file) => {
    const dateKey = file.dateKey || "unknown";
    const tenantId = file.tenantId || "unknown";

    if (!groups.has(dateKey)) {
      groups.set(dateKey, new Map());
    }

    const tenants = groups.get(dateKey);
    if (!tenants.has(tenantId)) {
      tenants.set(tenantId, []);
    }

    tenants.get(tenantId).push(file);
  });

  return Array.from(groups.entries())
    .sort((a, b) => b[0].localeCompare(a[0]))
    .map(([dateKey, tenants]) => ({
      dateKey,
      tenants: Array.from(tenants.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([tenantId, groupedFiles]) => ({
          tenantId,
          tenantName: groupedFiles.find((file) => file.tenantName)?.tenantName || "",
          files: groupedFiles.sort((a, b) => {
            if (a.isAggregate !== b.isAggregate) {
              return a.isAggregate ? -1 : 1;
            }
            return a.name.localeCompare(b.name);
          }),
        })),
    }));
}

export function buildScanTypeGroups(files, tenantId) {
  const tenantFiles = (files || []).filter((f) => f.tenantId === tenantId);
  const groups = new Map();

  tenantFiles.forEach((file) => {
    const key = file.scanType || "unknown";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(file);
  });

  return Array.from(groups.entries())
    .sort((a, b) => {
      if (a[0] === "all_scans") return -1;
      if (b[0] === "all_scans") return 1;
      return formatScanType(a[0]).localeCompare(formatScanType(b[0]));
    })
    .map(([scanType, groupFiles]) => ({
      scanType,
      files: [...groupFiles].sort((a, b) =>
        (b.dateKey || "").localeCompare(a.dateKey || "")
      ),
    }));
}

export function buildTenantFileGroups(files, tenantId) {
  const tenantFiles = (files || []).filter((f) => f.tenantId === tenantId);
  const groups = new Map();
  tenantFiles.forEach((file) => {
    const dk = file.dateKey || "unknown";
    if (!groups.has(dk)) groups.set(dk, []);
    groups.get(dk).push(file);
  });
  return Array.from(groups.entries())
    .sort((a, b) => b[0].localeCompare(a[0]))
    .map(([dateKey, groupFiles]) => ({
      dateKey,
      files: groupFiles.sort((a, b) => {
        if (a.isAggregate !== b.isAggregate) return a.isAggregate ? -1 : 1;
        return a.name.localeCompare(b.name);
      }),
    }));
}

export function getActiveFileMeta(files, activeFile) {
  return files.find((file) => file.name === activeFile) || parseFindingFileName(activeFile);
}
