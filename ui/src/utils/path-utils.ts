export interface PathSegment {
  name: string;
  path: string;
}

export interface HierarchyItem {
  name: string;
  path: string;
  isFolder: boolean;
  size?: number;
  lastModified?: string;
  etag?: string;
}

/**
 * Parse a full S3 path into breadcrumb segments
 * @example "/docs/2024/report.pdf" -> [{ name: "docs", path: "docs/" }, { name: "2024", path: "docs/2024/" }, { name: "report.pdf", path: "docs/2024/report.pdf" }]
 */
export function parseBreadcrumbs(fullPath: string): PathSegment[] {
  if (!fullPath || fullPath === "/") return [];

  const parts = fullPath.split("/").filter(Boolean);
  return parts.map((part, index) => ({
    name: part,
    path:
      parts.slice(0, index + 1).join("/") +
      (index < parts.length - 1 ? "/" : ""),
  }));
}

/**
 * Get the current prefix from a path
 * @example "docs/2024/report.pdf" -> "docs/2024/"
 */
export function getCurrentPrefix(fullPath: string): string {
  if (!fullPath || fullPath === "/") return "";
  const parts = fullPath.split("/").filter(Boolean);
  if (parts.length === 0) return "";
  // Remove last part (the file) and rejoin as folder prefix
  return parts.slice(0, -1).join("/") + "/";
}

/**
 * Build hierarchy from flat list of S3 objects
 * Groups objects by folder prefix at current level
 */
export function buildHierarchy(
  objects: Array<{
    key: string;
    size: number;
    last_modified: string;
    etag: string;
  }>,
  currentPrefix: string = "",
): HierarchyItem[] {
  const hierarchy: Map<string, HierarchyItem> = new Map();

  objects.forEach((obj) => {
    // Skip objects that don't match current prefix
    if (currentPrefix && !obj.key.startsWith(currentPrefix)) {
      return;
    }

    // Remove current prefix to get relative path
    const relative = obj.key.slice(currentPrefix.length);

    // Find first path separator
    const separatorIndex = relative.indexOf("/");

    if (separatorIndex === -1) {
      // It's a file at this level
      hierarchy.set(obj.key, {
        name: relative,
        path: obj.key,
        isFolder: false,
        size: obj.size,
        lastModified: obj.last_modified,
        etag: obj.etag,
      });
    } else {
      // It's a folder (prefix)
      const folderName = relative.slice(0, separatorIndex);
      const folderPath = currentPrefix + folderName + "/";

      if (!hierarchy.has(folderPath)) {
        hierarchy.set(folderPath, {
          name: folderName,
          path: folderPath,
          isFolder: true,
        });
      }
    }
  });

  return Array.from(hierarchy.values()).sort((a, b) => {
    // Folders first, then files, alphabetically
    if (a.isFolder !== b.isFolder) return a.isFolder ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}
