/**
 * ==============================================================================
 * HSE FIELD SAFETY PORTAL - GOOGLE APPS SCRIPT BACKEND
 * ==============================================================================
 * Production-ready backend for Work Permit Registration & Safety Observations.
 * Connected to Google Sheets database with atomic locks, audit logging, XSS
 * protection, formula injection prevention, and search/filter/dashboard services.
 * ==============================================================================
 */

// Global Constants for Sheet Names
const CONFIG = {
  SHEETS: {
    WORK_PERMITS: 'Work Permit Records',
    SAFETY_OBSERVATIONS: 'Safety Observations',
    LISTS: 'Lists',
    USERS: 'Users',
    AUDIT_LOG: 'Audit Log',
    SETTINGS: 'Settings',
    IDEMPOTENCY: '_Idempotency'
  },
  PREFIXES: {
    WORK_PERMIT: 'WP',
    SAFETY_OBSERVATION: 'SO'
  },
  LOCK_TIMEOUT_MS: 30000,
  DEFAULT_PAGE_SIZE: 15,
  SESSION_TTL_SECONDS: 8 * 60 * 60, // 8 hours
  CACHE_LISTS_SECONDS: 300,
  MAX_PAGE_SIZE: 100,
  // Canonical schemas (0-based indices)
  WP: {
    COLS: 14, // A–N
    ID: 0, SHIFT: 1, DEPT: 2, SECTION: 3, DATE: 4, WP_NUM: 5, TYPE: 6,
    ACTIVITY: 7, COMMENTS: 8, ISSUER: 9, RECEIVER: 10, CONTRACTOR: 11,
    SPONSOR: 12, STATUS: 13,
    HEADERS: [
      'S.N. / Record ID', 'Shift', 'Department', 'Section / Area', 'WP Date of Issue',
      'Work Permit Number', 'WP Type', 'Activity', 'Comments', 'Issuer Badge Number',
      'Receiver Badge Number', 'Contractor Company', 'Sponsoring Organization', 'Status'
    ]
  },
  SO: {
    COLS: 16, // A–P
    ID: 0, DATE: 1, DEPT: 2, FUNCTION: 3, EQUIP: 4, SECTION: 5, CONTRACTOR: 6,
    SPONSOR: 7, MAIN: 8, TYPE: 9, CATEGORY: 10, ROOT: 11, ACTION: 12,
    STATUS: 13, REPORTED: 14, REPORTED_BY: 15,
    HEADERS: [
      'S.N.', 'Observation Date', 'Department', 'Function / MFT Department', 'Equipment',
      'Section Area', 'PRC Contractor', 'Contractor Sponsoring Organization',
      'Main Safety Observation', 'Unsafe Act / Unsafe Condition', 'Category', 'Root Cause',
      'Safety Representative Interaction / Action Taken', 'Status', 'Reported', 'Reported By'
    ]
  }
};

/**
 * Web App Entry Point - Serves the HTML frontend interface
 */
function doGet(e) {
  return HtmlService.createTemplateFromFile('Index')
    .evaluate()
    .setTitle('DBN L&T HSE | DBN Project Field Safety Portal')
    .addMetaTag('viewport', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/**
 * Helper to include HTML fragments if needed
 */
function include(filename) {
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

/**
 * Returns active user details safely
 */
function getUserContext() {
  let email = 'Unknown User';
  try {
    email = Session.getActiveUser().getEmail() || Session.getEffectiveUser().getEmail() || 'anonymous@hse-portal.local';
  } catch (err) {
    email = 'anonymous@hse-portal.local';
  }
  return {
    email: email,
    timestamp: new Date().toISOString()
  };
}

// ==============================================================================
// SECURITY: SESSION + RBAC + IDEMPOTENCY
// ==============================================================================

/**
 * Creates a secure session after successful login.
 * Stored in CacheService AND Script Properties (cache can drop under load).
 */
function createSession(userPayload) {
  const token = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  const body = {
    username: userPayload.username,
    role: userPayload.role,
    roleView: !!userPayload.roleView,
    roleEdit: !!userPayload.roleEdit,
    roleUpload: !!userPayload.roleUpload,
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + (CONFIG.SESSION_TTL_SECONDS * 1000)
  };
  const json = JSON.stringify(body);
  try { CacheService.getScriptCache().put('sess:' + token, json, Math.min(CONFIG.SESSION_TTL_SECONDS, 21600)); } catch (e) {}
  try { PropertiesService.getScriptProperties().setProperty('sess:' + token, json); } catch (e) {}
  return token;
}

function readSessionRecord(token) {
  const key = 'sess:' + token;
  let raw = null;
  try { raw = CacheService.getScriptCache().get(key); } catch (e) {}
  if (!raw) {
    try { raw = PropertiesService.getScriptProperties().getProperty(key); } catch (e) {}
  }
  if (!raw) return null;
  let user;
  try { user = JSON.parse(raw); } catch (e) { return null; }
  if (user.expiresAt && Date.now() > Number(user.expiresAt)) {
    try { CacheService.getScriptCache().remove(key); } catch (e) {}
    try { PropertiesService.getScriptProperties().deleteProperty(key); } catch (e) {}
    return null;
  }
  // Sliding expiry
  user.expiresAt = Date.now() + (CONFIG.SESSION_TTL_SECONDS * 1000);
  const json = JSON.stringify(user);
  try { CacheService.getScriptCache().put(key, json, Math.min(CONFIG.SESSION_TTL_SECONDS, 21600)); } catch (e) {}
  try { PropertiesService.getScriptProperties().setProperty(key, json); } catch (e) {}
  return user;
}

/**
 * Validates session token. Returns { ok, user, response }.
 * required: 'view' | 'upload' | 'edit' | 'admin'
 */
function requireAuth(sessionToken, required) {
  const token = String(sessionToken || '').trim();
  const need = String(required || 'view').toLowerCase();

  // VIEW is allowed without token only as a last resort for recovery (still prefer session)
  if (!token) {
    if (need === 'view') {
      return {
        ok: true,
        user: { username: 'viewer', role: 'Viewer', roleView: true, roleEdit: false, roleUpload: false, ephemeral: true }
      };
    }
    return { ok: false, response: createResponse(false, 'Authentication required. Please sign in.', null, 'AUTH_REQUIRED') };
  }

  const user = readSessionRecord(token);
  if (!user) {
    if (need === 'view') {
      // Don't blank the whole dashboard on a transient session miss — allow read-only
      return {
        ok: true,
        user: { username: 'viewer', role: 'Viewer', roleView: true, roleEdit: false, roleUpload: false, ephemeral: true }
      };
    }
    return { ok: false, response: createResponse(false, 'Session expired. Please sign in again.', null, 'SESSION_EXPIRED') };
  }

  const role = String(user.role || '').toLowerCase();
  const isAdmin = role === 'super admin' || role === 'admin';
  if (need === 'admin' && !isAdmin) {
    return { ok: false, response: createResponse(false, 'Super Admin access required.', null, 'FORBIDDEN') };
  }
  if (need === 'edit' && !user.roleEdit && !isAdmin) {
    return { ok: false, response: createResponse(false, 'Edit permission required.', null, 'FORBIDDEN') };
  }
  if (need === 'upload' && !user.roleUpload && !user.roleEdit && !isAdmin) {
    return { ok: false, response: createResponse(false, 'Upload permission required.', null, 'FORBIDDEN') };
  }
  if (need === 'view' && !user.roleView && !isAdmin) {
    return { ok: false, response: createResponse(false, 'View permission required.', null, 'FORBIDDEN') };
  }
  return { ok: true, user: user };
}

function destroySession(sessionToken) {
  const token = String(sessionToken || '').trim();
  if (!token) return createResponse(true, 'Logged out');
  const key = 'sess:' + token;
  try { CacheService.getScriptCache().remove(key); } catch (e) {}
  try { PropertiesService.getScriptProperties().deleteProperty(key); } catch (e) {}
  return createResponse(true, 'Logged out');
}

/**
 * Idempotency: if clientUuid already processed, return prior result.
 * Stored briefly in CacheService + durable sheet for longer retention.
 */
function checkIdempotency(clientUuid) {
  const key = String(clientUuid || '').trim();
  if (!key) return null;
  const cache = CacheService.getScriptCache();
  const cached = cache.get('idem:' + key);
  if (cached) {
    try { return JSON.parse(cached); } catch (e) { return null; }
  }
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.IDEMPOTENCY);
    if (!sheet) return null;
    const last = sheet.getLastRow();
    if (last < 2) return null;
    // Scan last 200 keys only for performance
    const start = Math.max(2, last - 199);
    const n = last - start + 1;
    const vals = sheet.getRange(start, 1, n, 2).getValues();
    for (let i = vals.length - 1; i >= 0; i--) {
      if (String(vals[i][0]) === key) {
        try { return JSON.parse(String(vals[i][1])); } catch (e) { return { success: true, message: 'Duplicate request ignored', data: null, errorCode: 'IDEMPOTENT_REPLAY' }; }
      }
    }
  } catch (e) {}
  return null;
}

function storeIdempotency(clientUuid, responseObj) {
  const key = String(clientUuid || '').trim();
  if (!key || !responseObj) return;
  try {
    CacheService.getScriptCache().put('idem:' + key, JSON.stringify(responseObj), 21600); // 6h
  } catch (e) {}
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.IDEMPOTENCY);
    if (!sheet) {
      sheet = ss.insertSheet(CONFIG.SHEETS.IDEMPOTENCY);
      sheet.getRange(1, 1, 1, 3).setValues([['Client UUID', 'Response JSON', 'Timestamp']]);
      sheet.hideSheet();
    }
    sheet.appendRow([key, JSON.stringify(responseObj), new Date().toISOString()]);
    // Cap sheet size
    if (sheet.getLastRow() > 2000) {
      sheet.deleteRows(2, 500);
    }
  } catch (e) {}
}

/**
 * Batch-read sheet values with optional column limit (avoids full-grid getDataRange when possible).
 */
function getSheetValues(sheet, maxCols) {
  if (!sheet) return [];
  const lastRow = sheet.getLastRow();
  if (lastRow < 1) return [];
  const lastCol = Math.min(sheet.getLastColumn() || 1, maxCols || sheet.getLastColumn() || 1);
  return sheet.getRange(1, 1, lastRow, lastCol).getValues();
}

/**
 * Cached dropdown lists
 */
function getCachedLists() {
  const cache = CacheService.getScriptCache();
  const hit = cache.get('lists:v1');
  if (hit) {
    try { return JSON.parse(hit); } catch (e) {}
  }
  const data = getDropdownListsUncached();
  try { cache.put('lists:v1', JSON.stringify(data), CONFIG.CACHE_LISTS_SECONDS); } catch (e) {}
  return data || {};
}

function invalidateListsCache() {
  try { CacheService.getScriptCache().remove('lists:v1'); } catch (e) {}
}



// ==============================================================================
// SPREADSHEET INITIALIZATION & CONFIGURATION
// ==============================================================================

/**
 * Automatically creates and initializes all required sheets, headers, formats,
 * and default reference lists. Can be run manually or triggered automatically.
 */
function setupSpreadsheet() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'System is busy setting up database. Please try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    
    // Define exact headers for Sheet 1: Work Permit Records
    // Work Permit sheet: columns A–M only (no metadata after M)
    const wpHeaders = CONFIG.WP.HEADERS.slice();

    // Safety Observations — columns match operational sheet (no Shift; no trailing timestamps)
    // A SN | B Date | C Department | D Function/MFT | E Equipment | F Section Area |
    // G Contractor | H Sponsoring Org | I Main Obs | J Type | K Category | L Root Cause |
    // M Action Taken | N Status | O Reported | P Reported By
    const soHeaders = CONFIG.SO.HEADERS.slice();

    // Headers for Audit Log
    const auditHeaders = [
      'Timestamp',
      'User Email',
      'Action',
      'Module',
      'Record ID',
      'Target Ref',
      'Previous Value',
      'New Value',
      'Details'
    ];

    // Headers for Users (4 columns only)
    const userHeaders = ['Username', 'Password', 'Role', 'Status'];

    // Headers for Settings
    const settingHeaders = ['Setting Key', 'Setting Value', 'Description'];

    // 1. Initialize Work Permit Records Sheet
    initSheet(ss, CONFIG.SHEETS.WORK_PERMITS, wpHeaders, [
      { colIndex: 5, format: '@' }, // Work Permit Number as TEXT
      { colIndex: 9, format: '@' }, // Issuer Badge Number as TEXT
      { colIndex: 10, format: '@' } // Receiver Badge Number as TEXT
    ]);

    // 2. Initialize Safety Observations Sheet
    initSheet(ss, CONFIG.SHEETS.SAFETY_OBSERVATIONS, soHeaders, []);

    // 3. Initialize Lists Sheet
    initListsSheet(ss);

    // 4. Initialize Users Sheet (4 columns) + protect sensitive data
    initSheet(ss, CONFIG.SHEETS.USERS, userHeaders, [
      { colIndex: 1, format: '@' } // Password as TEXT
    ]);
    ensureUsersSheetStructure(ss);
    seedDefaultUsers(ss);
    protectUsersSheet(ss);

    // 5. Initialize Audit Log Sheet
    initSheet(ss, CONFIG.SHEETS.AUDIT_LOG, auditHeaders, []);

    // 6. Initialize Settings Sheet
    initSheet(ss, CONFIG.SHEETS.SETTINGS, settingHeaders, []);
    seedDefaultSettings(ss);

    // 7. Idempotency ledger (hidden)
    if (!ss.getSheetByName(CONFIG.SHEETS.IDEMPOTENCY)) {
      const idSheet = ss.insertSheet(CONFIG.SHEETS.IDEMPOTENCY);
      idSheet.getRange(1, 1, 1, 3).setValues([['Client UUID', 'Response JSON', 'Timestamp']]);
      idSheet.hideSheet();
    }

    // Log initialization event
    logAuditAction('SYSTEM_INIT', 'System', 'SYS-001', 'ALL', '', 'Spreadsheet Structure Initialized');

    return createResponse(true, 'Database sheets, headers, and reference lists successfully initialized.');
  } catch (err) {
    Logger.log('Error in setupSpreadsheet: ' + err.toString());
    return createResponse(false, 'Failed to initialize spreadsheet: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Helper to construct a clean sheet with styled headers and column formatting
 */
function initSheet(ss, sheetName, headers, textColumnFormats) {
  let sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
  }

  // Ensure header is set cleanly if sheet is empty or has missing columns
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(headers);
  } else {
    // Check if header row matches, if not update line 1
    const currentHeaders = sheet.getRange(1, 1, 1, Math.max(1, sheet.getLastColumn())).getValues()[0];
    if (currentHeaders.length < headers.length || currentHeaders[0] !== headers[0]) {
      sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    }
  }

  // Style Header Row: Dark Slate Header `#1e293b`, Bold White Text `#ffffff`
  const headerRange = sheet.getRange(1, 1, 1, headers.length);
  headerRange.setFontWeight('bold')
    .setBackground('#1e293b')
    .setFontColor('#ffffff')
    .setVerticalAlignment('middle')
    .setHorizontalAlignment('center');
  
  sheet.setRowHeight(1, 35);
  sheet.setFrozenRows(1);

  // Apply explicit TEXT format ('@') for specific numeric columns like Badges and WP Numbers
  if (textColumnFormats && textColumnFormats.length > 0) {
    textColumnFormats.forEach(item => {
      const colRange = sheet.getRange(2, item.colIndex + 1, Math.max(100, sheet.getMaxRows()), 1);
      colRange.setNumberFormat(item.format);
    });
  }

  // Clean empty trailing columns if necessary to avoid standard Sheet bloated columns
  const maxCols = sheet.getMaxColumns();
  if (maxCols > headers.length) {
    sheet.deleteColumns(headers.length + 1, maxCols - headers.length);
  }
}

/**
 * Populates default Reference Lists in the 'Lists' sheet cleanly
 */
function initListsSheet(ss) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.SHEETS.LISTS);
  }

  const listHeaders = [
    'Shift',
    'WP Type',
    'Department',
    'Section Area',
    'Category',
    'Unsafe Act/Condition',
    'Root Cause',
    'Status',
    'Contractor Company',
    'Sponsoring Organization',
    'Function MFT Dept'
  ];

  sheet.getRange(1, 1, 1, listHeaders.length)
    .setValues([listHeaders])
    .setFontWeight('bold')
    .setBackground('#0f172a')
    .setFontColor('#38bdf8')
    .setHorizontalAlignment('center');
  
  sheet.setFrozenRows(1);

  // Seed default data if column 1 is empty
  if (sheet.getLastRow() <= 1) {
    const defaultLists = {
      'Shift': ['Day', 'Night'],
      'WP Type': ['H', 'C', 'CS', 'EOLB'],
      'Department': ['PMD-Monomer I', 'PMD-Monomer II', 'Monomer I', 'Monomer II', 'Polymer', 'Utilities', 'Logistics', 'Maintenance', 'HSE', 'Engineering', 'Offsites & Logistics'],
      'Section Area': ['N200 STF Road F', 'STF 220 N 200', 'STF 220 N 201', 'NAPHTHA', 'R-410 Existing Pipe Rack', 'Tank Farm 1', 'Reactor Area', 'Boiler House', 'Substation 4', 'Warehouse A', 'Loading Rack', 'Utilities Hub'],
      'Category': ['PPE', 'Hot Work', 'Work at Height', 'Electrical Safety', 'Tools & Equipment', 'Housekeeping', 'Line Breaking', 'Fire Protection', 'Environmental', 'Chemical Handling', 'Vehicle Safety'],
      'Unsafe Act/Condition': ['Unsafe Act', 'Unsafe Condition', 'Safe Act / Good Practice'],
      'Root Cause': ['Negligence', 'Inadequate supervision', 'Short Cut', 'Lack of Training', 'Procedure Not Followed', 'Defective Tool/Equipment', 'Poor Housekeeping', 'Fatigue', 'Inadequate PPE', 'Communication Failure'],
      'Status': ['Open', 'In Progress', 'Close', 'Cancelled', 'Active'],
      'Contractor Company': ['L&T-DBN', 'Consolidated Contractors', 'Hyundai Engineering', 'Petrofac', 'Local Subcontractor', 'In-House'],
      'Sponsoring Organization': ['Revamp Projects Execution Department', 'Project Management Department', 'Maintenance Dept', 'Operations Dept', 'HSE Dept', 'Turnaround Dept'],
      'Function MFT Dept': ['Monomer I', 'Monomer II', 'Polymer', 'Utilities', 'HSE', 'Engineering', 'Projects MFT', 'Technical Services MFT']
    };

    // Calculate maximum rows needed
    let maxRows = 0;
    listHeaders.forEach(h => {
      if (defaultLists[h] && defaultLists[h].length > maxRows) {
        maxRows = defaultLists[h].length;
      }
    });

    const matrix = [];
    for (let r = 0; r < maxRows; r++) {
      const row = [];
      listHeaders.forEach(h => {
        const arr = defaultLists[h] || [];
        row.push(arr[r] || '');
      });
      matrix.push(row);
    }

    if (matrix.length > 0) {
      sheet.getRange(2, 1, matrix.length, listHeaders.length).setValues(matrix);
    }
  }

  // Trim columns
  if (sheet.getMaxColumns() > listHeaders.length) {
    sheet.deleteColumns(listHeaders.length + 1, sheet.getMaxColumns() - listHeaders.length);
  }
}

/**
 * Migrates Users sheet to 4-column layout: Username | Password | Role | Status
 * Preserves existing usernames/passwords when possible.
 */
function ensureUsersSheetStructure(ss) {
  let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet) {
    sheet = ss.insertSheet(CONFIG.SHEETS.USERS);
  }

  const targetHeaders = ['Username', 'Password', 'Role', 'Status'];
  const lastRow = sheet.getLastRow();
  const lastCol = sheet.getLastColumn();

  if (lastRow === 0) {
    sheet.getRange(1, 1, 1, 4).setValues([targetHeaders]);
  } else {
    const headers = sheet.getRange(1, 1, 1, Math.max(lastCol, 1)).getValues()[0].map(h => String(h || '').trim().toLowerCase());
    const isNewLayout = headers[0] === 'username' && headers[1] === 'password' && headers[2] === 'role' && headers[3] === 'status';

    if (!isNewLayout && lastRow >= 1) {
      // Migrate from legacy 8-column layout if present
      const data = sheet.getDataRange().getValues();
      const migrated = [targetHeaders];
      for (let i = 1; i < data.length; i++) {
        const row = data[i];
        if (!row[0]) continue;
        const username = String(row[0]).trim();
        const password = String(row[1] || '').trim().replace(/^'/, '');
        let role = 'Viewer';
        // Legacy: cols 3-5 were Role:View / Role:Edit / Role:Upload
        if (headers.indexOf('role') === 2 && headers.indexOf('status') === 3) {
          role = String(row[2] || 'Viewer').trim() || 'Viewer';
        } else {
          const boolVal = v => v === true || String(v).toLowerCase() === 'true' || String(v) === '1';
          const roleView = boolVal(row[3]);
          const roleEdit = boolVal(row[4]);
          const roleUpload = boolVal(row[5]);
          if (String(username).toLowerCase() === 'admin' || (roleView && roleEdit && roleUpload)) {
            role = 'Super Admin';
          } else if (roleEdit) {
            role = 'Editor';
          } else if (roleUpload) {
            role = 'Uploader';
          } else {
            role = 'Viewer';
          }
        }
        const statusIdx = headers.indexOf('status');
        const status = statusIdx >= 0 ? String(row[statusIdx] || 'Active').trim() : 'Active';
        migrated.push([username, password, role, status || 'Active']);
      }
      sheet.clearContents();
      if (migrated.length > 0) {
        sheet.getRange(1, 1, migrated.length, 4).setValues(migrated);
      }
    } else {
      sheet.getRange(1, 1, 1, 4).setValues([targetHeaders]);
    }
  }

  // Style header
  const headerRange = sheet.getRange(1, 1, 1, 4);
  headerRange.setFontWeight('bold').setBackground('#1e293b').setFontColor('#ffffff')
    .setVerticalAlignment('middle').setHorizontalAlignment('center');
  sheet.setFrozenRows(1);
  sheet.setRowHeight(1, 35);
  sheet.getRange(2, 2, Math.max(100, sheet.getMaxRows()), 1).setNumberFormat('@');

  // Trim extra columns
  const maxCols = sheet.getMaxColumns();
  if (maxCols > 4) {
    sheet.deleteColumns(5, maxCols - 4);
  }
}

/**
 * Protects the Users sheet so humans cannot freely view/edit passwords in the grid.
 * Script execution still retains access for login & admin APIs.
 */
function protectUsersSheet(ss) {
  try {
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return;

    // Remove prior protections on this sheet to avoid duplicates
    const protections = sheet.getProtections(SpreadsheetApp.ProtectionType.SHEET);
    protections.forEach(p => {
      try { p.remove(); } catch (e) { /* ignore */ }
    });

    const protection = sheet.protect().setDescription('Users sheet — password protected. Manage users only via Super Admin in the portal.');
    protection.setWarningOnly(false);

    // Only the file owner may edit the sheet directly
    const me = Session.getEffectiveUser();
    protection.addEditor(me);
    protection.removeEditors(protection.getEditors().filter(e => e.getEmail() !== me.getEmail()));
    if (protection.canDomainEdit()) {
      protection.setDomainEdit(false);
    }
  } catch (err) {
    Logger.log('protectUsersSheet: ' + err.toString());
  }
}

/**
 * Seeds initial users if empty OR ensures the built-in admin account exists.
 * Layout: Username | Password (hashed) | Role | Status
 */
function seedDefaultUsers(ss) {
  const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet) return;
  // Only seed when sheet is empty — never overwrite production credentials
  if (sheet.getLastRow() > 1) return;
  sheet.getRange(2, 1, 1, 4).setValues([['admin', hashPassword('Admin@2026'), 'Super Admin', 'Active']]);
  sheet.getRange(2, 2).setNumberFormat('@');
  Logger.log('Bootstrap admin created (change password after first login).');
}

/**
 * Force-reset built-in accounts to known passwords (stored as hashes).
 * Run from Apps Script editor if login is stuck.
 */
function resetDefaultPasswords() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet) {
    setupSpreadsheet();
    sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  }
  if (!sheet) return createResponse(false, 'Users sheet could not be created.');

  ensureUsersSheetStructure(ss);
  sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);

  const defaults = {
    admin:       ['admin',       hashPassword('Admin@2026'), 'Super Admin', 'Active'],
    hse_officer: ['hse_officer', hashPassword('Hse@2026'),   'Uploader',    'Active']
  };

  const data = sheet.getDataRange().getValues();
  const found = { admin: false, hse_officer: false };

  for (let i = 1; i < data.length; i++) {
    const uname = String(data[i][0] || '').trim().toLowerCase();
    if (defaults[uname]) {
      sheet.getRange(i + 1, 1, 1, 4).setValues([defaults[uname]]);
      sheet.getRange(i + 1, 2).setNumberFormat('@');
      found[uname] = true;
    }
  }
  Object.keys(defaults).forEach(key => {
    if (!found[key]) {
      sheet.appendRow(defaults[key]);
      sheet.getRange(sheet.getLastRow(), 2).setNumberFormat('@');
    }
  });

  protectUsersSheet(ss);
  logAuditAction('RESET_PASSWORDS', 'Auth', 'admin', '', '', 'Default portal passwords reset (hashed)');
  return createResponse(true, 'Default users restored (hashed). Login with admin / Admin@2026');
}

/**
 * Maps Role column value → permission flags used by the frontend.
 */
function roleToPermissions(role) {
  const r = String(role || '').trim().toLowerCase();
  if (r === 'super admin' || r === 'admin' || r === 'superadmin') {
    return { roleView: true, roleEdit: true, roleUpload: true, roleLabel: 'Super Admin' };
  }
  if (r === 'editor') {
    return { roleView: true, roleEdit: true, roleUpload: false, roleLabel: 'Editor' };
  }
  if (r === 'uploader') {
    return { roleView: true, roleEdit: false, roleUpload: true, roleLabel: 'Uploader' };
  }
  // Viewer / default
  return { roleView: true, roleEdit: false, roleUpload: false, roleLabel: 'Viewer' };
}

// ==============================================================================
// PASSWORD HASHING (salted SHA-256)
// Storage format: v1$<saltHex>$<sha256Hex>
// ==============================================================================

/**
 * Generates a random hex salt (16 bytes → 32 hex chars).
 */
function generateSalt() {
  const bytes = [];
  for (let i = 0; i < 16; i++) {
    bytes.push(Math.floor(Math.random() * 256));
  }
  return bytes.map(b => ('0' + b.toString(16)).slice(-2)).join('');
}

/**
 * SHA-256 digest of a string → lowercase hex.
 */
function sha256Hex(str) {
  const raw = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(str), Utilities.Charset.UTF_8);
  return raw.map(function (b) {
    const v = (b < 0) ? b + 256 : b;
    return ('0' + v.toString(16)).slice(-2);
  }).join('');
}

/**
 * Returns true if the stored value looks like a hashed password.
 */
function isPasswordHashed(stored) {
  return /^v1\$[0-9a-f]{32}\$[0-9a-f]{64}$/i.test(String(stored || '').trim());
}

/**
 * Hashes a plaintext password with a new random salt.
 * @returns {string} v1$salt$hash
 */
function hashPassword(plainPassword) {
  const salt = generateSalt();
  const digest = sha256Hex(salt + String(plainPassword));
  return 'v1$' + salt + '$' + digest;
}

/**
 * Verifies a plaintext password against a stored value.
 * Supports:
 *  - hashed form v1$salt$hash
 *  - legacy plaintext (exact match) for migration
 */
function verifyPassword(plainPassword, storedValue) {
  const stored = String(storedValue || '').trim().replace(/^'/, '');
  const plain = String(plainPassword || '');
  if (!stored || plain === '') return false;

  if (isPasswordHashed(stored)) {
    const parts = stored.split('$');
    // parts: ['v1', salt, hash]
    if (parts.length !== 3) return false;
    const salt = parts[1];
    const expected = parts[2].toLowerCase();
    const actual = sha256Hex(salt + plain);
    return actual === expected;
  }

  // Legacy plaintext
  return stored === plain;
}

/**
 * If stored password is still plaintext and matches, upgrade it to a hash in-place.
 * @returns {string|null} new hash if upgraded, otherwise null
 */
function upgradePasswordHashIfNeeded(sheet, rowIndex1Based, plainPassword, storedValue) {
  const stored = String(storedValue || '').trim().replace(/^'/, '');
  if (isPasswordHashed(stored)) return null;
  if (stored !== String(plainPassword || '')) return null;
  const hashed = hashPassword(plainPassword);
  sheet.getRange(rowIndex1Based, 2).setValue(hashed).setNumberFormat('@');
  return hashed;
}

/**
 * Verifies the admin password against the Users sheet (for sensitive actions).
 * Accepts hashed or legacy plaintext; upgrades plaintext on success.
 */
function confirmAdminPassword(adminPassword) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
  if (!sheet || sheet.getLastRow() <= 1) return false;
  const cleanPass = String(adminPassword || '').trim().replace(/^'/, '');
  if (!cleanPass) return false;
  const data = sheet.getDataRange().getValues();
  for (let i = 1; i < data.length; i++) {
    const uname = String(data[i][0] || '').trim().toLowerCase();
    const stored = String(data[i][1] || '').trim().replace(/^'/, '');
    const role = String(data[i][2] || '').trim().toLowerCase();
    const status = String(data[i][3] || '').trim().toLowerCase();
    const isAdminAccount = uname === 'admin' || role === 'super admin' || role === 'admin';
    if (!isAdminAccount || status !== 'active') continue;
    if (verifyPassword(cleanPass, stored)) {
      upgradePasswordHashIfNeeded(sheet, i + 1, cleanPass, stored);
      return true;
    }
  }
  return false;
}

/**
 * Seeds default key-value system settings
 */
function seedDefaultSettings(ss) {
  const sheet = ss.getSheetByName(CONFIG.SHEETS.SETTINGS);
  if (sheet && sheet.getLastRow() <= 1) {
    const defaultSettings = [
      ['APP_NAME', 'HSE Field Safety Portal', 'Application Title'],
      ['WP_ID_PREFIX', 'WP-', 'Prefix for Work Permit Record IDs'],
      ['SO_ID_PREFIX', 'SO-', 'Prefix for Safety Observation IDs'],
      ['CHECK_DUPLICATE_PERMITS', 'TRUE', 'Check duplicate WP # + Date on submission'],
      ['REQUIRE_BADGE_NUMBERS', 'TRUE', 'Enforce badge number formatting'],
      ['DEFAULT_PAGE_SIZE', '15', 'Records per page in search tables']
    ];
    sheet.getRange(2, 1, defaultSettings.length, 3).setValues(defaultSettings);
  }
}

// ==============================================================================
// REFERENCE LISTS & CONFIG READERS
// ==============================================================================

/**
 * Fetches dynamic dropdown options from the 'Lists' sheet
 */
function getDropdownLists(sessionToken) {
  try {
    return createResponse(true, 'Dropdown reference lists fetched successfully', getCachedLists());
  } catch (err) {
    return createResponse(false, 'Failed to read dropdown lists: ' + err.message);
  }
}

function getDropdownListsUncached() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
  if (!sheet) {
    setupSpreadsheet();
    sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
  }
  if (!sheet) return {};
  const data = getSheetValues(sheet, 30);
  if (data.length <= 1) return {};
  const headers = data[0];
  const result = {};
  headers.forEach(function (h, colIdx) {
    if (!h) return;
    const options = [];
    for (let r = 1; r < data.length; r++) {
      const val = data[r][colIdx];
      if (val !== undefined && val !== null && String(val).trim() !== '') {
        options.push(String(val).trim());
      }
    }
    result[String(h)] = options;
  });
  return result;
}

/**
 * Adds a new option to a specific list in the 'Lists' sheet
 */
function addListValue(listName, newValue) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'System busy. Try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.LISTS);
    if (!sheet) return createResponse(false, 'Lists sheet not found');

    const cleanVal = sanitizeInput(newValue);
    if (!cleanVal) return createResponse(false, 'Value cannot be empty');

    const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    const colIdx = headers.indexOf(listName);

    if (colIdx === -1) {
      return createResponse(false, `List '${listName}' does not exist.`);
    }

    // Find first empty cell in column or append below last row
    const colValues = sheet.getRange(1, colIdx + 1, sheet.getLastRow(), 1).getValues();
    let targetRow = colValues.length + 1;

    for (let i = 1; i < colValues.length; i++) {
      if (!colValues[i][0] || String(colValues[i][0]).trim() === '') {
        targetRow = i + 1;
        break;
      }
    }

    sheet.getRange(targetRow, colIdx + 1).setValue(cleanVal);
    logAuditAction('ADD_LIST_OPTION', 'Lists', listName, cleanVal, '', `Added option '${cleanVal}' to list '${listName}'`);

    invalidateListsCache();
    return createResponse(true, `Option '${cleanVal}' added to list '${listName}' successfully.`);
  } catch (err) {
    return createResponse(false, 'Failed to add option: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// MODULE A: WORK PERMIT REGISTRATION
// ==============================================================================

/**
 * Records an existing Work Permit entry into Sheet 1: Work Permit Records
 */
function submitWorkPermitRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'upload');
  if (!auth.ok) return auth.response;

  const clientUuid = String(formData.clientUuid || '').trim();
  if (clientUuid) {
    const prior = checkIdempotency(clientUuid);
    if (prior) return prior;
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy recording data. Please try submitting again in a moment.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet) {
      setupSpreadsheet();
      sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    }

    // 1. Server-side Sanitization & Validation
    const shift = sanitizeInput(formData.shift);
    const department = sanitizeInput(formData.department);
    const section = sanitizeInput(formData.section);
    const wpDate = sanitizeInput(formData.wpDateOfIssue);
    const wpNumber = sanitizeInput(formData.workPermitNumber);
    const wpType = sanitizeInput(formData.wpType);
    const activity = sanitizeInput(formData.activity);
    const comments = sanitizeInput(formData.comments);
    const issuerBadge = formatBadgeNumber(formData.issuerBadgeNumber);
    const receiverBadge = formatBadgeNumber(formData.receiverBadgeNumber);
    const contractor = sanitizeInput(formData.contractorCompany);
    const sponsoringOrg = sanitizeInput(formData.sponsoringOrganization);

    // Basic required field assertions
    if (!wpNumber || !wpDate || !department || !shift || !wpType) {
      return createResponse(false, 'Please fill in all mandatory fields: Shift, Department, WP Date, WP Number, WP Type.');
    }

    // 2. Duplicate Detection: Check WP Number + Date
    const checkDuplicate = getSettingValue('CHECK_DUPLICATE_PERMITS') !== 'FALSE';
    if (checkDuplicate && sheet.getLastRow() > 1) {
      const existingRows = sheet.getDataRange().getValues();
      // Row 0 is header. Col 4 = WP Date, Col 5 = WP Number, Col 16 = Status
      for (let i = 1; i < existingRows.length; i++) {
        const rowDateStr = formatDateValue(existingRows[i][4]);
        const rowWPNum = String(existingRows[i][5]).replace(/^'/, '').trim();
        const rowStatus = existingRows[i].length > 16 ? String(existingRows[i][16] || '').trim() : '';

        if (rowWPNum === wpNumber && rowDateStr === wpDate && rowStatus !== 'Cancelled' && rowStatus !== 'Archived') {
          return createResponse(false, `Duplicate Record Error: Work Permit #${wpNumber} is already recorded for date ${wpDate} (Record ID: ${existingRows[i][0]}).`, null, 'DUPLICATE_PERMIT');
        }
      }
    }

    // 3. Auto-Generate Record ID from total/max serial (e.g. WP-2026-00001)
    const recordId = generateNextID(sheet, CONFIG.PREFIXES.WORK_PERMIT);
    const userContext = getUserContext();
    const timestampStr = formatTimestamp(new Date());

    // 4. Columns A–M only (13 cols) — nothing recorded after column M
    const newRow = [
      recordId,
      shift,
      department,
      section,
      wpDate,
      "'" + wpNumber,
      wpType,
      activity,
      comments || '',
      "'" + issuerBadge,
      "'" + receiverBadge,
      contractor || '',
      sponsoringOrg || '',
      'Active'                  // N Status (soft-delete uses Archived)
    ];

    const prevDataRow = sheet.getLastRow(); // header=1 or last data row
    sheet.appendRow(newRow);
    const newRowIndex = sheet.getLastRow();

    // Format painter: copy formatting from previous data row (or header styles)
    try {
      if (prevDataRow >= 2) {
        sheet.getRange(prevDataRow, 1, 1, CONFIG.WP.COLS).copyFormatToRange(sheet, 1, CONFIG.WP.COLS, newRowIndex, newRowIndex);
      } else if (prevDataRow === 1) {
        // First data row — clone header row format as a baseline then override data styles
        sheet.getRange(1, 1, 1, 13).copyFormatToRange(sheet, 1, 13, newRowIndex, newRowIndex);
        sheet.getRange(newRowIndex, 1, 1, 13)
          .setFontWeight('normal')
          .setBackground(null);
      }
    } catch (fmtErr) {
      Logger.log('WP format copy: ' + fmtErr);
    }

    // Enforce text format on number-like columns (survives format paste)
    sheet.getRange(newRowIndex, 6).setNumberFormat('@');   // F WP #
    sheet.getRange(newRowIndex, 10).setNumberFormat('@');  // J Issuer
    sheet.getRange(newRowIndex, 11).setNumberFormat('@');  // K Receiver

    // Ensure sheet display does not expand past M for new structure
    try {
      if (sheet.getMaxColumns() > 13) {
        // Do not delete existing extra columns (legacy data); just avoid writing them
      }
    } catch (e) {}

    // 5. Audit Log
    logAuditAction('CREATE', 'Work Permit', recordId, wpNumber, '', `Work Permit #${wpNumber} registered by ${userContext.email}`);

    const okRes = createResponse(true, 'Work Permit Record Created Successfully!', {
      recordId: recordId,
      workPermitNumber: wpNumber,
      dateOfIssue: wpDate,
      timestamp: timestampStr,
      status: 'Active',
      clientUuid: clientUuid || null
    });
    if (clientUuid) storeIdempotency(clientUuid, okRes);
    return okRes;

  } catch (err) {
    Logger.log('Error in submitWorkPermitRecord: ' + err.toString());
    return createResponse(false, 'Failed to record Work Permit: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Updates an existing Work Permit row by recordId.
 */
function updateWorkPermitRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'edit');
  if (!auth.ok) return auth.response;
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const recordId = String((formData && formData.recordId) || '').trim();
    if (!recordId) return createResponse(false, 'Record ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Work Permit sheet not found.');

    const data = sheet.getDataRange().getValues();
    let targetRow = -1;
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === recordId) {
        targetRow = i + 1;
        break;
      }
    }
    if (targetRow < 0) return createResponse(false, 'Record not found: ' + recordId);

    const shift = sanitizeInput(formData.shift);
    const department = sanitizeInput(formData.department);
    const section = sanitizeInput(formData.section);
    const wpDate = sanitizeInput(formData.wpDateOfIssue);
    const wpNumber = sanitizeInput(formData.workPermitNumber);
    const wpType = sanitizeInput(formData.wpType);
    const activity = sanitizeInput(formData.activity);
    const comments = sanitizeInput(formData.comments);
    const issuerBadge = formatBadgeNumber(formData.issuerBadgeNumber);
    const receiverBadge = formatBadgeNumber(formData.receiverBadgeNumber);
    const contractor = sanitizeInput(formData.contractorCompany);
    const sponsoringOrg = sanitizeInput(formData.sponsoringOrganization);
    if (!wpNumber || !wpDate || !department || !shift || !wpType) {
      return createResponse(false, 'Please fill in all mandatory fields.');
    }

    // Update columns B–M only (nothing after M)
    sheet.getRange(targetRow, 2, 1, 12).setValues([[
      shift, department, section, wpDate,
      "'" + wpNumber, wpType, activity, comments || '',
      "'" + issuerBadge, "'" + receiverBadge,
      contractor || '', sponsoringOrg || ''
    ]]);
    // Keep formatting consistent with neighboring data row
    try {
      const fmtSrc = targetRow > 2 ? targetRow - 1 : targetRow;
      sheet.getRange(fmtSrc, 1, 1, 13).copyFormatToRange(sheet, 1, 13, targetRow, targetRow);
    } catch (e) {}
    sheet.getRange(targetRow, 6).setNumberFormat('@');
    sheet.getRange(targetRow, 10).setNumberFormat('@');
    sheet.getRange(targetRow, 11).setNumberFormat('@');

    logAuditAction('UPDATE', 'Work Permit', recordId, wpNumber, '', `Work Permit ${recordId} updated`);
    return createResponse(true, 'Work Permit updated successfully.', { recordId: recordId });
  } catch (err) {
    return createResponse(false, 'Failed to update Work Permit: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Deletes a Work Permit row by recordId.
 */
/**
 * Archives (soft-deletes) a Work Permit. Permanent delete only via purgeWorkPermitRecord (Super Admin).
 * @param {string|Object} recordIdOrPayload - id string or {recordId, sessionToken, hardDelete}
 */
function deleteWorkPermitRecord(recordIdOrPayload, maybeToken) {
  let recordId, sessionToken, hardDelete = false;
  if (recordIdOrPayload && typeof recordIdOrPayload === 'object') {
    recordId = recordIdOrPayload.recordId;
    sessionToken = recordIdOrPayload.sessionToken;
    hardDelete = !!recordIdOrPayload.hardDelete;
  } else {
    recordId = recordIdOrPayload;
    sessionToken = maybeToken;
  }
  const auth = requireAuth(sessionToken, hardDelete ? 'admin' : 'edit');
  if (!auth.ok) return auth.response;

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const id = String(recordId || '').trim();
    if (!id) return createResponse(false, 'Record ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Work Permit sheet not found.');

    const data = getSheetValues(sheet, CONFIG.WP.COLS);
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === id) {
        const wpNumber = String(data[i][CONFIG.WP.WP_NUM] || '').replace(/^'/, '');
        if (hardDelete && String(auth.user.role).toLowerCase().indexOf('super') !== -1) {
          sheet.deleteRow(i + 1);
          logAuditAction('PURGE', 'Work Permit', id, wpNumber, 'Active', 'Permanently deleted by Super Admin');
          return createResponse(true, 'Work Permit permanently deleted.');
        }
        // Soft delete → Status Archived (ensure Status column exists)
        const statusCol = CONFIG.WP.STATUS + 1; // 1-based
        if (sheet.getLastColumn() < statusCol) {
          sheet.getRange(1, statusCol).setValue('Status');
        }
        const prev = String(data[i][CONFIG.WP.STATUS] || 'Active');
        sheet.getRange(i + 1, statusCol).setValue('Archived');
        logAuditAction('ARCHIVE', 'Work Permit', id, wpNumber, prev, 'Archived');
        return createResponse(true, 'Work Permit archived successfully.');
      }
    }
    return createResponse(false, 'Record not found: ' + id);
  } catch (err) {
    return createResponse(false, 'Failed to archive Work Permit: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// MODULE B: SAFETY OBSERVATIONS
// ==============================================================================

/**
 * Records a new HSE Safety Observation into Sheet 2: Safety Observations
 */
function submitSafetyObservationRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'upload');
  if (!auth.ok) return auth.response;

  const clientUuid = String(formData.clientUuid || '').trim();
  if (clientUuid) {
    const prior = checkIdempotency(clientUuid);
    if (prior) return prior;
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy recording observation. Please try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet) {
      setupSpreadsheet();
      sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    }

    // 1. Server-side Sanitization & Validation
    const obsDateRaw = sanitizeInput(formData.observationDate);
    const department = sanitizeInput(formData.department);
    const functionDept = sanitizeInput(formData.functionMftDept);
    const sectionArea = sanitizeInput(formData.sectionArea);
    const equipment = sanitizeInput(formData.equipment);
    const prcContractor = sanitizeInput(formData.prcContractor);
    const contractorSponsoringOrg = sanitizeInput(formData.contractorSponsoringOrg);
    const mainObservation = sanitizeInput(formData.mainSafetyObservation);
    const unsafeType = sanitizeInput(formData.unsafeActCondition);
    const category = sanitizeInput(formData.category);
    const rootCause = sanitizeInput(formData.rootCause);
    const actionTaken = sanitizeInput(formData.actionTaken);
    let status = sanitizeInput(formData.status) || 'Open';
    if (String(status).toLowerCase() === 'close') status = 'Closed';
    const reported = sanitizeInput(formData.reported);
    const reportedBy = sanitizeInput(formData.reportedBy) || getUserContext().email;

    // Required field validation
    if (!obsDateRaw || !department || !mainObservation || !unsafeType || !category) {
      return createResponse(false, 'Please fill in required fields: Date, Department, Category, Observation Type, and Main Observation description.');
    }

    // Date as mm/dd/yyyy to match existing sheet style
    const obsDate = formatDateMDY(obsDateRaw);

    // 2. Sequential SN from last observation count (e.g. 1074 after 1073)
    const obsId = generateNextObservationSerial(sheet);
    const userContext = getUserContext();

    // 3. Row matches operational sheet layout (16 columns A–P) — NO Shift, NO timestamps
    // A SN | B Date | C Department | D Function/MFT | E Equipment | F Section Area |
    // G Contractor | H Sponsoring | I Main | J Type | K Category | L Root |
    // M Action | N Status | O Reported | P Reported By
    const newRow = [
      obsId,                          // A
      obsDate,                        // B  mm/dd/yyyy
      department,                     // C
      functionDept || '',             // D
      equipment || '',                // E
      sectionArea || '',              // F
      prcContractor || '',            // G
      contractorSponsoringOrg || '',  // H
      mainObservation,                // I
      unsafeType,                     // J
      category,                       // K
      rootCause || '',                // L
      actionTaken || '',              // M
      status,                         // N
      reported || '',                 // O
      reportedBy || ''                // P
    ];

    const prevRow = sheet.getLastRow();
    sheet.appendRow(newRow);
    const newRowIndex = sheet.getLastRow();

    // Format painter from previous data row
    try {
      if (prevRow >= 2) {
        sheet.getRange(prevRow, 1, 1, 16).copyFormatToRange(sheet, 1, 16, newRowIndex, newRowIndex);
      }
    } catch (e) {}

    // Force date column display / text-friendly
    try {
      sheet.getRange(newRowIndex, 2).setNumberFormat('m/d/yyyy');
    } catch (e) {}

    // 4. Audit Log
    logAuditAction('CREATE', 'Safety Observation', String(obsId), String(obsId), '', `Observation ${obsId} (${unsafeType} - ${category}) created by ${userContext.email}`);

    const okRes = createResponse(true, 'Safety Observation Recorded Successfully', {
      observationId: String(obsId),
      date: obsDate,
      category: category,
      type: unsafeType,
      status: status,
      timestamp: formatTimestamp(new Date()),
      clientUuid: clientUuid || null
    });
    if (clientUuid) storeIdempotency(clientUuid, okRes);
    return okRes;

  } catch (err) {
    Logger.log('Error in submitSafetyObservationRecord: ' + err.toString());
    return createResponse(false, 'Failed to record Safety Observation: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}


/**
 * Updates a Safety Observation by observationId.
 */
function updateSafetyObservationRecord(formData) {
  formData = formData || {};
  const auth = requireAuth(formData.sessionToken, 'edit');
  if (!auth.ok) return auth.response;
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const obsId = String((formData && formData.observationId) || '').trim();
    if (!obsId) return createResponse(false, 'Observation ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Safety Observations sheet not found.');

    const data = sheet.getDataRange().getValues();
    let targetRow = -1;
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === obsId) {
        targetRow = i + 1;
        break;
      }
    }
    if (targetRow < 0) return createResponse(false, 'Record not found: ' + obsId);

    const obsDate = sanitizeInput(formData.observationDate);
    const department = sanitizeInput(formData.department);
    const sectionArea = sanitizeInput(formData.sectionArea);
    const mainObservation = sanitizeInput(formData.mainSafetyObservation);
    const actionTaken = sanitizeInput(formData.actionTaken);
    const status = sanitizeInput(formData.status) || String(data[targetRow - 1][15] || 'Open');
    const reportedBy = sanitizeInput(formData.reportedBy) || String(data[targetRow - 1][17] || '');

    // Operational layout: B date, C dept, F section, I main, M action, N status, P reportedBy
    // Legacy layout (with Shift): B date, E dept, F section, J main, N action, P status, R reportedBy
    const firstData = sheet.getRange(2, 1, 1, Math.min(6, sheet.getLastColumn())).getValues()[0] || [];
    const legacy = String(firstData[0] || '').toUpperCase().indexOf('SO-') === 0 ||
      ['day', 'night'].indexOf(String(firstData[2] || '').toLowerCase()) >= 0;

    if (obsDate) {
      sheet.getRange(targetRow, 2).setValue(formatDateMDY(obsDate));
      try { sheet.getRange(targetRow, 2).setNumberFormat('m/d/yyyy'); } catch (e) {}
    }
    if (legacy) {
      if (department) sheet.getRange(targetRow, 5).setValue(department);
      if (sectionArea) sheet.getRange(targetRow, 6).setValue(sectionArea);
      if (mainObservation) sheet.getRange(targetRow, 10).setValue(mainObservation);
      if (actionTaken !== undefined && actionTaken !== null) sheet.getRange(targetRow, 14).setValue(actionTaken);
      sheet.getRange(targetRow, 16).setValue(status);
      if (reportedBy) sheet.getRange(targetRow, 18).setValue(reportedBy);
    } else {
      if (department) sheet.getRange(targetRow, 3).setValue(department);
      if (sectionArea) sheet.getRange(targetRow, 6).setValue(sectionArea);
      if (mainObservation) sheet.getRange(targetRow, 9).setValue(mainObservation);
      if (actionTaken !== undefined && actionTaken !== null) sheet.getRange(targetRow, 13).setValue(actionTaken);
      sheet.getRange(targetRow, 14).setValue(status);
      if (reportedBy) sheet.getRange(targetRow, 16).setValue(reportedBy);
    }

    logAuditAction('UPDATE', 'Safety Observation', obsId, obsId, '', 'Observation updated via UI');
    return createResponse(true, 'Safety Observation updated successfully.', { observationId: obsId });
  } catch (err) {
    return createResponse(false, 'Failed to update observation: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Deletes a Safety Observation by observationId.
 */
function deleteSafetyObservationRecord(observationIdOrPayload, maybeToken) {
  let obsId, sessionToken, hardDelete = false;
  if (observationIdOrPayload && typeof observationIdOrPayload === 'object') {
    obsId = observationIdOrPayload.observationId || observationIdOrPayload.recordId;
    sessionToken = observationIdOrPayload.sessionToken;
    hardDelete = !!observationIdOrPayload.hardDelete;
  } else {
    obsId = observationIdOrPayload;
    sessionToken = maybeToken;
  }
  const auth = requireAuth(sessionToken, hardDelete ? 'admin' : 'edit');
  if (!auth.ok) return auth.response;

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'Server busy. Please try again.');
  }
  try {
    const id = String(obsId || '').trim();
    if (!id) return createResponse(false, 'Observation ID is required.');

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(false, 'Safety Observations sheet not found.');

    const data = getSheetValues(sheet, CONFIG.SO.COLS);
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim() === id) {
        if (hardDelete) {
          sheet.deleteRow(i + 1);
          logAuditAction('PURGE', 'Safety Observation', id, id, '', 'Permanently deleted by Super Admin');
          return createResponse(true, 'Observation permanently deleted.');
        }
        const prev = String(data[i][CONFIG.SO.STATUS] || '');
        sheet.getRange(i + 1, CONFIG.SO.STATUS + 1).setValue('Archived');
        logAuditAction('ARCHIVE', 'Safety Observation', id, id, prev, 'Archived');
        return createResponse(true, 'Observation archived successfully.');
      }
    }
    return createResponse(false, 'Record not found: ' + id);
  } catch (err) {
    return createResponse(false, 'Failed to archive observation: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}


// ==============================================================================
// SEARCH, FILTER & PAGINATION SERVICES
// ==============================================================================

/**
 * Searches and paginates Work Permit Records
 */
function getWorkPermitRecords(params) {
  params = params || {};
  const auth = requireAuth(params.sessionToken, 'view');
  if (!auth.ok) return auth.response;
  try {
    params = params || {};
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    if (!sheet) return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });

    const rawData = sheet.getDataRange().getValues();
    if (rawData.length <= 1) {
      return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });
    }

    let rows = [];

    for (let i = 1; i < rawData.length; i++) {
      const r = rawData[i];
      rows.push({
        recordId: String(r[0] || ''),
        shift: String(r[1] || ''),
        department: String(r[2] || ''),
        section: String(r[3] || ''),
        wpDateOfIssue: formatDateValue(r[4]),
        workPermitNumber: String(r[5] || '').replace(/^'/, ''),
        wpType: String(r[6] || ''),
        activity: String(r[7] || ''),
        comments: String(r[8] || ''),
        issuerBadgeNumber: String(r[9] || '').replace(/^'/, ''),
        receiverBadgeNumber: String(r[10] || '').replace(/^'/, ''),
        contractorCompany: String(r[11] || ''),
        sponsoringOrganization: String(r[12] || ''),
        createdDateTime: '',
        createdBy: '',
        lastUpdatedDateTime: '',
        status: (function () {
          // Col N (index 13) is Status when present; ignore timestamp-looking legacy values
          if (r.length <= 13) return 'Active';
          const s = String(r[13] || '').trim();
          if (!s) return 'Active';
          const low = s.toLowerCase();
          if (low === 'active' || low === 'open' || low === 'closed' || low === 'close' ||
              low === 'cancelled' || low === 'archived' || low === 'in progress') return s;
          // Legacy timestamp or other junk in that column
          return 'Active';
        })()
      });
    }

    // Filter Logic
    const query = (params.search || '').toLowerCase().trim();
    const dept = (params.department || '').trim();
    const shift = (params.shift || '').trim();
    const wpType = (params.wpType || '').trim();
    const status = (params.status || '').trim();
    const startDate = params.startDate || '';
    const endDate = params.endDate || '';
    const issuerBadge = String(params.issuerBadge || '').trim().toLowerCase();
    const receiverBadge = String(params.receiverBadge || '').trim().toLowerCase();

    let filtered = rows.filter(item => {
      if (!params.includeArchived && String(item.status || '').toLowerCase() === 'archived') return false;
      if (status && item.status !== status) return false;
      if (dept && item.department !== dept) return false;
      if (shift && item.shift !== shift) return false;
      if (wpType && item.wpType !== wpType) return false;
      if (startDate && item.wpDateOfIssue < startDate) return false;
      if (endDate && item.wpDateOfIssue > endDate) return false;
      if (issuerBadge && !String(item.issuerBadgeNumber || '').toLowerCase().includes(issuerBadge)) return false;
      if (receiverBadge && !String(item.receiverBadgeNumber || '').toLowerCase().includes(receiverBadge)) return false;

      if (query) {
        const text = `${item.recordId} ${item.workPermitNumber} ${item.activity} ${item.section} ${item.contractorCompany} ${item.issuerBadgeNumber} ${item.receiverBadgeNumber}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    // Sort by serial number DESC; fallback to WP date DESC when serial missing
    filtered.sort((a, b) => compareBySerialThenDate(
      a.recordId, b.recordId, a.wpDateOfIssue, b.wpDateOfIssue
    ));

    // Pagination
    const page = parseInt(params.page, 10) || 1;
    const pageSize = parseInt(params.pageSize, 10) || CONFIG.DEFAULT_PAGE_SIZE;
    const totalRecords = filtered.length;
    const totalPages = Math.ceil(totalRecords / pageSize) || 1;
    const startIndex = (page - 1) * pageSize;
    const paginatedRecords = filtered.slice(startIndex, startIndex + pageSize);

    return createResponse(true, 'Records fetched', {
      records: paginatedRecords,
      total: totalRecords,
      page: page,
      totalPages: totalPages,
      pageSize: pageSize
    });
  } catch (err) {
    Logger.log('Error in getWorkPermitRecords: ' + err.toString());
    return createResponse(false, 'Failed to fetch Work Permit records: ' + err.message);
  }
}

/**
 * Searches and paginates Safety Observation Records
 */
function getSafetyObservationRecords(params) {
  params = params || {};
  const auth = requireAuth(params.sessionToken, 'view');
  if (!auth.ok) return auth.response;
  try {
    params = params || {};
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);
    if (!sheet) return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });

    const rawData = sheet.getDataRange().getValues();
    if (rawData.length <= 1) {
      return createResponse(true, 'No records found', { records: [], total: 0, page: 1 });
    }

    let rows = [];

    for (let i = 1; i < rawData.length; i++) {
      const r = rawData[i];
      // Canonical operational layout only (A–P)
      rows.push({
        observationId: String(r[CONFIG.SO.ID] || ''),
        observationDate: formatDateValue(r[CONFIG.SO.DATE]),
        shift: '',
        functionMftDept: String(r[CONFIG.SO.FUNCTION] || ''),
        department: String(r[CONFIG.SO.DEPT] || ''),
        sectionArea: String(r[CONFIG.SO.SECTION] || ''),
        equipment: String(r[CONFIG.SO.EQUIP] || ''),
        prcContractor: String(r[CONFIG.SO.CONTRACTOR] || ''),
        contractorSponsoringOrg: String(r[CONFIG.SO.SPONSOR] || ''),
        mainSafetyObservation: String(r[CONFIG.SO.MAIN] || ''),
        unsafeActCondition: String(r[CONFIG.SO.TYPE] || ''),
        category: String(r[CONFIG.SO.CATEGORY] || ''),
        rootCause: String(r[CONFIG.SO.ROOT] || ''),
        actionTaken: String(r[CONFIG.SO.ACTION] || ''),
        followUp: '',
        status: String(r[CONFIG.SO.STATUS] || ''),
        reported: String(r[CONFIG.SO.REPORTED] || ''),
        reportedBy: String(r[CONFIG.SO.REPORTED_BY] || ''),
        createdDateTime: '',
        lastUpdatedDateTime: ''
      });
    }

    // Filters
    const query = (params.search || '').toLowerCase().trim();
    const dept = (params.department || '').trim();
    const category = (params.category || '').trim();
    const unsafeType = (params.unsafeType || '').trim();
    const status = (params.status || '').trim();
    const startDate = params.startDate || '';
    const endDate = params.endDate || '';
    const reportedBy = String(params.reportedBy || '').trim().toLowerCase();

    let filtered = rows.filter(item => {
      if (!params.includeArchived && String(item.status || '').toLowerCase() === 'archived') return false;
      if (status && item.status !== status) return false;
      if (dept && item.department !== dept) return false;
      if (category && item.category !== category) return false;
      if (unsafeType && item.unsafeActCondition !== unsafeType) return false;
      if (startDate && item.observationDate < startDate) return false;
      if (endDate && item.observationDate > endDate) return false;
      if (reportedBy && !String(item.reportedBy || '').toLowerCase().includes(reportedBy)) return false;

      if (query) {
        const text = `${item.observationId} ${item.mainSafetyObservation} ${item.actionTaken} ${item.sectionArea} ${item.prcContractor} ${item.rootCause} ${item.reportedBy}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    // Sort by serial number DESC; fallback to observation date DESC when serial missing
    filtered.sort((a, b) => compareBySerialThenDate(
      a.observationId, b.observationId, a.observationDate, b.observationDate
    ));

    // Pagination
    const page = parseInt(params.page, 10) || 1;
    const pageSize = parseInt(params.pageSize, 10) || CONFIG.DEFAULT_PAGE_SIZE;
    const totalRecords = filtered.length;
    const totalPages = Math.ceil(totalRecords / pageSize) || 1;
    const startIndex = (page - 1) * pageSize;
    const paginatedRecords = filtered.slice(startIndex, startIndex + pageSize);

    return createResponse(true, 'Observations fetched', {
      records: paginatedRecords,
      total: totalRecords,
      page: page,
      totalPages: totalPages,
      pageSize: pageSize
    });
  } catch (err) {
    Logger.log('Error in getSafetyObservationRecords: ' + err.toString());
    return createResponse(false, 'Failed to fetch Safety Observations: ' + err.message);
  }
}

// ==============================================================================
// UPDATE & STATUS CHANGE SERVICES
// ==============================================================================

/**
 * Updates status of a Work Permit or Safety Observation
 */
function updateRecordStatus(moduleName, recordId, newStatus, comments) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) {
    return createResponse(false, 'System busy. Please try again.');
  }

  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheetName = moduleName === 'Work Permit' ? CONFIG.SHEETS.WORK_PERMITS : CONFIG.SHEETS.SAFETY_OBSERVATIONS;
    let sheet = ss.getSheetByName(sheetName);

    if (!sheet) return createResponse(false, 'Target sheet not found.');

    const data = sheet.getDataRange().getValues();
    let targetRowIndex = -1;
    let oldStatus = '';
    let statusColIndex = moduleName === 'Work Permit' ? 17 : 16; // 1-based index
    let updatedColIndex = moduleName === 'Work Permit' ? 16 : 20;

    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]) === recordId) {
        targetRowIndex = i + 1;
        oldStatus = String(data[i][statusColIndex - 1]);
        break;
      }
    }

    if (targetRowIndex === -1) {
      return createResponse(false, `Record ID '${recordId}' not found.`);
    }

    const nowStr = formatTimestamp(new Date());
    sheet.getRange(targetRowIndex, statusColIndex).setValue(newStatus);
    sheet.getRange(targetRowIndex, updatedColIndex).setValue(nowStr);

    const user = getUserContext().email;
    logAuditAction('UPDATE_STATUS', moduleName, recordId, recordId, oldStatus, `Status changed to '${newStatus}' by ${user}. Notes: ${comments || 'N/A'}`);

    return createResponse(true, `Status for ${recordId} updated to '${newStatus}' successfully.`);
  } catch (err) {
    Logger.log('Error in updateRecordStatus: ' + err.toString());
    return createResponse(false, 'Failed to update record: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// DASHBOARD STATISTICS SERVICE
// ==============================================================================

/**
 * Returns {start,end} YYYY-MM-DD for dashboard period filter.
 * period: today | yesterday | weekly | monthly | total
 */
function getDashboardPeriodRange(period) {
  const p = String(period || 'total').toLowerCase().trim();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayStr = formatDateValue(today);

  if (p === 'today') return { start: todayStr, end: todayStr };

  if (p === 'yesterday') {
    const y = new Date(today);
    y.setDate(y.getDate() - 1);
    const ys = formatDateValue(y);
    return { start: ys, end: ys };
  }

  if (p === 'weekly') {
    const s = new Date(today);
    s.setDate(s.getDate() - 6);
    return { start: formatDateValue(s), end: todayStr };
  }

  if (p === 'monthly') {
    const s = new Date(today);
    s.setDate(s.getDate() - 29);
    return { start: formatDateValue(s), end: todayStr };
  }

  return { start: '', end: '' }; // total — no date filter
}

function isDateInRange(dateStr, start, end) {
  if (!dateStr) return false;
  if (start && dateStr < start) return false;
  if (end && dateStr > end) return false;
  return true;
}

/**
 * Aggregates high-level metrics for the HSE Dashboard.
 * @param {string} period - today | yesterday | weekly | monthly | total
 */
function getDashboardStats(period, sessionToken) {
  // period may be object {period, sessionToken} from client
  if (period && typeof period === 'object') {
    sessionToken = period.sessionToken;
    period = period.period;
  }
  const auth = requireAuth(sessionToken, 'view');
  if (!auth.ok) return auth.response;
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const wpSheet = ss.getSheetByName(CONFIG.SHEETS.WORK_PERMITS);
    const soSheet = ss.getSheetByName(CONFIG.SHEETS.SAFETY_OBSERVATIONS);

    const todayStr = formatDateValue(new Date());
    const range = getDashboardPeriodRange(period);
    const filterByPeriod = !!(range.start || range.end);

    // --- Work Permits Aggregations ---
    let totalWp = 0;
    let todayWp = 0;
    let dayShiftWp = 0;
    let nightShiftWp = 0;
    const wpByDept = {};
    const wpByType = {};
    const wpDaily = {};
    const wpByStatus = {};
    const wpByTypeStatus = {};

    if (wpSheet && wpSheet.getLastRow() > 1) {
      const wpData = wpSheet.getDataRange().getValues();
      for (let i = 1; i < wpData.length; i++) {
        const row = wpData[i];
        const status = row.length > 16 ? (String(row[16] || 'Active').trim() || 'Active') : 'Active';
        if (status === 'Archived') continue;

        const dateStr = formatDateValue(row[4]);
        // Always track "today" for KPI subtitle even when period filtered
        if (dateStr === todayStr) todayWp++;

        if (filterByPeriod && !isDateInRange(dateStr, range.start, range.end)) continue;

        totalWp++;
        const shift = String(row[1]);
        const dept = String(row[2]) || 'Unassigned';
        const type = String(row[6]) || 'Other';

        if (shift.toLowerCase().includes('day')) dayShiftWp++;
        if (shift.toLowerCase().includes('night')) nightShiftWp++;

        wpByDept[dept] = (wpByDept[dept] || 0) + 1;
        wpByType[type] = (wpByType[type] || 0) + 1;
        wpByStatus[status] = (wpByStatus[status] || 0) + 1;
        if (!wpByTypeStatus[type]) wpByTypeStatus[type] = {};
        wpByTypeStatus[type][status] = (wpByTypeStatus[type][status] || 0) + 1;
        if (dateStr) wpDaily[dateStr] = (wpDaily[dateStr] || 0) + 1;
      }
    }

    // --- Safety Observations Aggregations ---
    let totalSo = 0;
    let todaySo = 0;
    let openSo = 0;
    let closedSo = 0;
    let unsafeActs = 0;
    let unsafeConditions = 0;
    const soByCategory = {};
    const soByDept = {};
    const soDaily = {};
    const soByReporter = {};
    const soByRootCause = {};

    if (soSheet && soSheet.getLastRow() > 1) {
      const soData = soSheet.getDataRange().getValues();
      for (let i = 1; i < soData.length; i++) {
        const row = soData[i];
        const status = String(row[CONFIG.SO.STATUS] || '');
        const dept = String(row[CONFIG.SO.DEPT] || '') || 'Unassigned';
        const unsafeType = String(row[CONFIG.SO.TYPE] || '');
        const category = String(row[CONFIG.SO.CATEGORY] || '') || 'General';
        const rootCause = String(row[CONFIG.SO.ROOT] || '').trim() || 'Unspecified';
        const reporter = String(row[CONFIG.SO.REPORTED_BY] || '').trim() || 'Unassigned';

        if (status === 'Archived') continue;

        const dateStr = formatDateValue(row[1]);
        if (dateStr === todayStr) todaySo++;

        if (filterByPeriod && !isDateInRange(dateStr, range.start, range.end)) continue;

        totalSo++;

        if (status === 'Open' || status === 'In Progress') openSo++;
        if (status === 'Closed' || status === 'Close') closedSo++;

        if (unsafeType.toLowerCase().includes('act')) unsafeActs++;
        if (unsafeType.toLowerCase().includes('condition')) unsafeConditions++;

        soByCategory[category] = (soByCategory[category] || 0) + 1;
        soByDept[dept] = (soByDept[dept] || 0) + 1;
        soByRootCause[rootCause] = (soByRootCause[rootCause] || 0) + 1;
        if (dateStr) soDaily[dateStr] = (soDaily[dateStr] || 0) + 1;
        if (reporter && reporter !== 'Unassigned') soByReporter[reporter] = (soByReporter[reporter] || 0) + 1;
        else if (reporter === 'Unassigned') soByReporter[reporter] = (soByReporter[reporter] || 0) + 1;
      }
    }

    return createResponse(true, 'Dashboard metrics calculated successfully', {
      period: String(period || 'total'),
      range: range,
      workPermits: {
        total: totalWp,
        today: todayWp,
        dayShift: dayShiftWp,
        nightShift: nightShiftWp,
        byDepartment: wpByDept,
        byType: wpByType,
        byStatus: wpByStatus,
        byTypeStatus: wpByTypeStatus,
        daily: wpDaily
      },
      safetyObservations: {
        total: totalSo,
        today: todaySo,
        open: openSo,
        closed: closedSo,
        unsafeActs: unsafeActs,
        unsafeConditions: unsafeConditions,
        byCategory: soByCategory,
        byDepartment: soByDept,
        byRootCause: soByRootCause,
        daily: soDaily,
        byReporter: soByReporter
      },
      lastUpdated: formatTimestamp(new Date())
    });

  } catch (err) {
    Logger.log('Error in getDashboardStats: ' + err.toString());
    return createResponse(false, 'Failed to compile dashboard metrics: ' + err.message);
  }
}

// ==============================================================================
// DATABASE EXPORT (CSV via client download)
// ==============================================================================

/**
 * Exports sheet data as CSV (base64) — no UrlFetchApp / external_request scope required.
 * Excel and Google Sheets open these files cleanly.
 * @param {string} which - 'permits' | 'observations' | 'both'
 */
function exportSheetData(which, sessionToken) {
  if (which && typeof which === 'object') {
    sessionToken = which.sessionToken;
    which = which.which || which.mode || 'both';
  }
  const auth = requireAuth(sessionToken, 'admin');
  if (!auth.ok) return auth.response;
  try {
    const mode = String(which || 'both').toLowerCase().trim();
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const stamp = Utilities.formatDate(new Date(), Session.getScriptTimeZone() || 'GMT', 'yyyy-MM-dd');

    const wantPermits = (mode === 'permits' || mode === 'both' || mode === 'permit' || mode === 'wp');
    const wantObs = (mode === 'observations' || mode === 'both' || mode === 'observation' || mode === 'so');

    if (!wantPermits && !wantObs) {
      return createResponse(false, 'Unknown export option. Use permits, observations, or both.');
    }

    function sheetToCsvBase64(sheetName) {
      const sheet = ss.getSheetByName(sheetName);
      if (!sheet || sheet.getLastRow() < 1) {
        return Utilities.base64Encode(Utilities.newBlob(sheetName + '\n').getBytes());
      }
      const values = sheet.getDataRange().getValues();
      const lines = [];
      for (let r = 0; r < values.length; r++) {
        const cols = values[r].map(function (cell) {
          if (cell instanceof Date) {
            try { return formatTimestamp(cell); } catch (e) { return String(cell); }
          }
          let s = String(cell == null ? '' : cell).replace(/^'/, '');
          if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
          return s;
        });
        // skip fully empty data rows (keep header)
        if (r > 0 && cols.every(function (c) { return String(c).trim() === ''; })) continue;
        lines.push(cols.join(','));
      }
      const csv = lines.join('\r\n');
      // UTF-8 BOM helps Excel open UTF-8 correctly
      const blob = Utilities.newBlob('\uFEFF' + csv, 'text/csv', sheetName + '.csv');
      return Utilities.base64Encode(blob.getBytes());
    }

    const files = [];
    if (wantPermits) {
      files.push({
        filename: 'Work_Permit_Records_' + stamp + '.csv',
        base64: sheetToCsvBase64(CONFIG.SHEETS.WORK_PERMITS),
        mime: 'text/csv;charset=utf-8'
      });
    }
    if (wantObs) {
      files.push({
        filename: 'Safety_Observations_' + stamp + '.csv',
        base64: sheetToCsvBase64(CONFIG.SHEETS.SAFETY_OBSERVATIONS),
        mime: 'text/csv;charset=utf-8'
      });
    }

    if (!files.length) {
      return createResponse(false, 'No sheets available to export.');
    }

    logAuditAction('EXPORT', 'Database', mode, '', '', 'Sheet data exported as CSV: ' + mode);
    return createResponse(true, 'Export data ready', { files: files });
  } catch (err) {
    Logger.log('exportSheetData: ' + err.toString());
    return createResponse(false, 'Failed to export sheet data: ' + err.message);
  }
}

// ==============================================================================
// AUDIT LOG & SETTINGS SERVICES
// ==============================================================================

/**
 * Appends an entry to the Audit Log sheet
 */
function logAuditAction(action, moduleName, recordId, targetRef, prevValue, newValue) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.AUDIT_LOG);
    if (!sheet) return;

    const userContext = getUserContext();
    const timestampStr = formatTimestamp(new Date());

    sheet.appendRow([
      timestampStr,
      userContext.email,
      action,
      moduleName,
      recordId,
      targetRef || '',
      prevValue || '',
      newValue || '',
      `System Log`
    ]);
  } catch (err) {
    Logger.log('Audit Log error: ' + err.toString());
  }
}

/**
 * Fetches recent audit logs
 */
function getAuditLogs(limit, sessionToken) {
  if (limit && typeof limit === 'object') {
    sessionToken = limit.sessionToken;
    limit = limit.limit;
  }
  const auth = requireAuth(sessionToken, 'admin');
  if (!auth.ok) return auth.response;
  try {
    limit = limit || 50;
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.AUDIT_LOG);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(true, 'No audit logs', []);

    const raw = sheet.getDataRange().getValues();
    const logs = [];
    const max = Math.min(raw.length - 1, limit);

    for (let i = raw.length - 1; i >= raw.length - max; i--) {
      const r = raw[i];
      logs.push({
        timestamp: formatTimestamp(r[0]),
        user: String(r[1]),
        action: String(r[2]),
        module: String(r[3]),
        recordId: String(r[4]),
        targetRef: String(r[5]),
        prevValue: String(r[6]),
        newValue: String(r[7])
      });
    }

    return createResponse(true, 'Audit logs retrieved', logs);
  } catch (err) {
    return createResponse(false, 'Failed to fetch audit logs: ' + err.message);
  }
}

/**
 * Reads setting value from Settings sheet
 */
function getSettingValue(keyName) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.SETTINGS);
    if (!sheet) return '';
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).toUpperCase() === keyName.toUpperCase()) {
        return String(data[i][1]).trim();
      }
    }
  } catch (err) {
    Logger.log('Error reading setting: ' + err.toString());
  }
  return '';
}

// ==============================================================================
// USER AUTHENTICATION & MANAGEMENT
// ==============================================================================

/**
 * Verifies user credentials against the Users sheet (4-col: Username|Password|Role|Status).
 */
function logoutUser(sessionToken) {
  destroySession(sessionToken);
  logAuditAction('LOGOUT', 'Auth', '', '', '', 'User signed out');
  return createResponse(true, 'Logged out');
}

function verifySession(sessionToken) {
  const auth = requireAuth(sessionToken, 'view');
  if (!auth.ok) return auth.response;
  return createResponse(true, 'Session valid', auth.user);
}

function verifyUserLogin(username, password) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) {
      setupSpreadsheet();
      sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    }
    ensureUsersSheetStructure(ss);
    seedDefaultUsers(ss);
    SpreadsheetApp.flush();
    sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);

    if (!sheet || sheet.getLastRow() <= 1) {
      return createResponse(false, 'No users configured. Run resetDefaultPasswords() from the script editor.');
    }

    const data = sheet.getDataRange().getValues();
    const cleanUser = String(username || '').trim().toLowerCase();
    const cleanPass = String(password || '').trim().replace(/^'/, '');
    if (!cleanUser || !cleanPass) {
      return createResponse(false, 'Please enter both username and password.');
    }

    const blockedStatuses = ['inactive', 'disabled', 'suspended', 'deleted', 'locked', 'false', '0', 'no'];

    for (let i = 1; i < data.length; i++) {
      const rowUser = String(data[i][0] || '').trim().toLowerCase();
      const rowPass = String(data[i][1] || '').trim().replace(/^'/, '');
      const rowRole = String(data[i][2] || 'Viewer').trim();
      const rowStatus = String(data[i][3] || '').trim().toLowerCase();

      if (rowUser === cleanUser && verifyPassword(cleanPass, rowPass)) {
        if (rowStatus && blockedStatuses.indexOf(rowStatus) !== -1) {
          return createResponse(false, 'This account is inactive. Contact your administrator.');
        }
        // Transparent migration: upgrade legacy plaintext → salted hash
        upgradePasswordHashIfNeeded(sheet, i + 1, cleanPass, rowPass);
        const perms = roleToPermissions(rowRole);
        logAuditAction('LOGIN', 'Auth', String(data[i][0]), '', '', `User '${data[i][0]}' signed in`);
        const payload = {
          username:   String(data[i][0]).trim(),
          fullName:   String(data[i][0]).trim(),
          role:       perms.roleLabel,
          roleView:   perms.roleView,
          roleEdit:   perms.roleEdit,
          roleUpload: perms.roleUpload,
          department: ''
        };
        payload.sessionToken = createSession(payload);
        payload.expiresIn = CONFIG.SESSION_TTL_SECONDS;
        return createResponse(true, 'Login successful', payload);
      }
    }
    return createResponse(false, 'Invalid username or password. Please try again.');
  } catch (err) {
    Logger.log('Login error: ' + err.toString());
    return createResponse(false, 'Authentication error: ' + err.message);
  }
}

/**
 * Returns list of users WITHOUT passwords (safe for table display).
 */
function getUsers() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ensureUsersSheetStructure(ss);
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet || sheet.getLastRow() <= 1) return createResponse(true, 'No users found', []);
    const data = sheet.getDataRange().getValues();
    const users = [];
    for (let i = 1; i < data.length; i++) {
      if (!data[i][0]) continue;
      const roleRaw = String(data[i][2] || 'Viewer').trim();
      const perms = roleToPermissions(roleRaw);
      users.push({
        rowIndex:   i + 1,
        username:   String(data[i][0]).trim(),
        role:       perms.roleLabel,
        roleView:   perms.roleView,
        roleEdit:   perms.roleEdit,
        roleUpload: perms.roleUpload,
        status:     String(data[i][3] || 'Active').trim()
      });
    }
    return createResponse(true, 'Users fetched', users);
  } catch (err) {
    return createResponse(false, 'Failed to fetch users: ' + err.message);
  }
}

/**
 * Returns a single user for admin view/edit — requires Super Admin password.
 * Password field is never returned as the raw hash; only a masked indicator.
 * For edits, admin sets a new plaintext password which is re-hashed on save.
 */
function getUserSecure(username, adminPassword) {
  try {
    if (!confirmAdminPassword(adminPassword)) {
      return createResponse(false, 'Invalid admin password. Access denied.');
    }
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');
    const data = sheet.getDataRange().getValues();
    const target = String(username || '').trim().toLowerCase();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0] || '').trim().toLowerCase() === target) {
        const perms = roleToPermissions(data[i][2]);
        const stored = String(data[i][1] || '').trim().replace(/^'/, '');
        logAuditAction('VIEW_USER', 'Users', String(data[i][0]), '', '', 'User record viewed after admin confirmation');
        return createResponse(true, 'User loaded', {
          username: String(data[i][0]).trim(),
          // Never expose hash; show placeholder so UI knows a password exists
          password: '',
          passwordSet: !!stored,
          passwordHashed: isPasswordHashed(stored),
          role:     perms.roleLabel,
          status:   String(data[i][3] || 'Active').trim()
        });
      }
    }
    return createResponse(false, 'User not found.');
  } catch (err) {
    return createResponse(false, 'Failed to load user: ' + err.message);
  }
}

/**
 * Creates a new portal user. Layout: Username | Password | Role | Status
 */
function createUser(userData) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ensureUsersSheetStructure(ss);
    let sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');

    const username = sanitizeInput(userData.username);
    const password = String(userData.password || '').trim();
    let role = String(userData.role || 'Viewer').trim();
    const status = String(userData.status || 'Active').trim() || 'Active';

    // Normalize role label
    role = roleToPermissions(role).roleLabel;

    if (!username || !password) {
      return createResponse(false, 'Username and Password are required.');
    }
    if (username.toLowerCase() === 'admin') {
      return createResponse(false, 'Username "admin" is reserved.');
    }

    if (sheet.getLastRow() > 1) {
      const existing = sheet.getRange(2, 1, sheet.getLastRow(), 1).getValues();
      for (let i = 0; i < existing.length; i++) {
        if (String(existing[i][0]).trim().toLowerCase() === username.toLowerCase()) {
          return createResponse(false, `Username '${username}' already exists.`);
        }
      }
    }

    const hashed = hashPassword(password);
    sheet.appendRow([username, hashed, role, status]);
    sheet.getRange(sheet.getLastRow(), 2).setNumberFormat('@');
    logAuditAction('CREATE_USER', 'Users', username, username, '', `User '${username}' (${role}) created with hashed password`);
    return createResponse(true, `User '${username}' created successfully.`);
  } catch (err) {
    return createResponse(false, 'Failed to create user: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Updates an existing user. Requires Super Admin password.
 * Can change password, role, status. Username is the key (not changed).
 */
function updateUser(userData) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    if (!confirmAdminPassword(userData.adminPassword)) {
      return createResponse(false, 'Invalid admin password. Access denied.');
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');

    const username = String(userData.username || '').trim();
    if (!username) return createResponse(false, 'Username is required.');

    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0] || '').trim().toLowerCase() === username.toLowerCase()) {
        // Only re-hash when a new plaintext password is provided
        let newPasswordStored = String(data[i][1] || '').trim().replace(/^'/, '');
        if (userData.password !== undefined && userData.password !== null && String(userData.password).trim() !== '') {
          newPasswordStored = hashPassword(String(userData.password).trim());
        }

        let newRole = userData.role !== undefined && userData.role !== null && String(userData.role).trim() !== ''
          ? roleToPermissions(userData.role).roleLabel
          : roleToPermissions(data[i][2]).roleLabel;
        let newStatus = userData.status !== undefined && userData.status !== null && String(userData.status).trim() !== ''
          ? String(userData.status).trim()
          : String(data[i][3] || 'Active').trim();

        // Protect built-in admin role/status
        if (username.toLowerCase() === 'admin') {
          newRole = 'Super Admin';
          if (String(newStatus).toLowerCase() !== 'active') {
            return createResponse(false, 'The admin account must remain Active.');
          }
        }

        sheet.getRange(i + 1, 2).setValue(newPasswordStored).setNumberFormat('@');
        sheet.getRange(i + 1, 3).setValue(newRole);
        sheet.getRange(i + 1, 4).setValue(newStatus);

        logAuditAction('UPDATE_USER', 'Users', username, username, '', `Updated role=${newRole}, status=${newStatus}`);
        return createResponse(true, `User '${username}' updated successfully.`);
      }
    }
    return createResponse(false, `User '${username}' not found.`);
  } catch (err) {
    return createResponse(false, 'Failed to update user: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

/**
 * Deletes a portal user. Requires Super Admin password.
 */
function deleteUser(username, adminPassword) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(CONFIG.LOCK_TIMEOUT_MS)) return createResponse(false, 'System busy. Try again.');
  try {
    if (!confirmAdminPassword(adminPassword)) {
      return createResponse(false, 'Invalid admin password. Access denied.');
    }

    const cleanName = String(username || '').trim();
    if (!cleanName) return createResponse(false, 'Username is required.');
    if (cleanName.toLowerCase() === 'admin') {
      return createResponse(false, 'The built-in admin account cannot be deleted.');
    }

    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(CONFIG.SHEETS.USERS);
    if (!sheet) return createResponse(false, 'Users sheet not found.');
    const data = sheet.getDataRange().getValues();
    for (let i = 1; i < data.length; i++) {
      if (String(data[i][0]).trim().toLowerCase() === cleanName.toLowerCase()) {
        sheet.deleteRow(i + 1);
        logAuditAction('DELETE_USER', 'Users', cleanName, cleanName, '', `User '${cleanName}' deleted`);
        return createResponse(true, `User '${cleanName}' removed successfully.`);
      }
    }
    return createResponse(false, `User '${cleanName}' not found.`);
  } catch (err) {
    return createResponse(false, 'Failed to delete user: ' + err.message);
  } finally {
    lock.releaseLock();
  }
}

// ==============================================================================
// UTILITIES & HELPER FUNCTIONS
// ==============================================================================

/**
 * Extracts the trailing serial number from an ID like WP-2026-00012 or SO-2026-1001.
 * Returns null if no numeric serial is present.
 */
function parseRecordSerial(idValue) {
  const s = String(idValue || '').trim();
  if (!s) return null;
  // Match trailing digits after last hyphen, or pure integer
  const m = s.match(/(\d+)\s*$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return isNaN(n) ? null : n;
}

/**
 * Scans column A of a sheet and returns the highest serial number found
 * for the given prefix (e.g. "WP" or "SO"). Year-agnostic so sequences
 * never reset incorrectly and support values above 999 / 9999.
 */
function getLastSerialNum(sheet, prefix) {
  if (!sheet || sheet.getLastRow() <= 1) return 0;
  const lastRow = sheet.getLastRow();
  const numRows = lastRow - 1; // data rows only
  if (numRows < 1) return 0;

  const firstColValues = sheet.getRange(2, 1, numRows, 1).getValues();
  const prefixUpper = String(prefix || '').toUpperCase();
  let maxSeq = 0;

  firstColValues.forEach(row => {
    const idStr = String(row[0] || '').trim();
    if (!idStr) return;
    // Accept PREFIX-YYYY-##### or PREFIX-#####
    const upper = idStr.toUpperCase();
    if (prefixUpper && upper.indexOf(prefixUpper) !== 0) return;
    const seq = parseRecordSerial(idStr);
    if (seq !== null && seq > maxSeq) maxSeq = seq;
  });

  return maxSeq;
}

/**
 * Returns the latest entry date (YYYY-MM-DD) found in a date column (1-based).
 * Used as a fallback when serial numbers are missing.
 */
function getLatestEntryDate(sheet, dateColIndex1Based) {
  if (!sheet || sheet.getLastRow() <= 1) return '';
  const lastRow = sheet.getLastRow();
  const numRows = lastRow - 1;
  if (numRows < 1) return '';

  const col = Math.max(1, dateColIndex1Based || 1);
  const values = sheet.getRange(2, col, numRows, 1).getValues();
  let latest = '';
  values.forEach(row => {
    const d = formatDateValue(row[0]);
    if (d && (!latest || d > latest)) latest = d;
  });
  return latest;
}

/**
 * Sort comparator: higher serial first; if serial missing, newer date first.
 */
function compareBySerialThenDate(aId, bId, aDate, bDate) {
  const sa = parseRecordSerial(aId);
  const sb = parseRecordSerial(bId);
  if (sa !== null && sb !== null && sa !== sb) return sb - sa;
  if (sa !== null && sb === null) return -1; // numbered before unnumbered
  if (sa === null && sb !== null) return 1;
  const da = String(aDate || '');
  const db = String(bDate || '');
  if (da !== db) return db.localeCompare(da); // newest date first
  // Final tie-break: full ID string descending
  return String(bId || '').localeCompare(String(aId || ''));
}

/**
 * Generates next sequential ID: PREFIX-YYYY-#####
 * Serial continues past 999 / 9999 (minimum 5-digit zero-pad, grows as needed).
 */
function generateNextID(sheet, prefix) {
  const year = new Date().getFullYear();
  const maxSeq = getLastSerialNum(sheet, prefix);
  // Total permit/observation count (data rows) so serial tracks overall volume
  const totalRows = sheet && sheet.getLastRow() > 1 ? (sheet.getLastRow() - 1) : 0;
  const nextSeq = Math.max(maxSeq, totalRows) + 1;
  // At least 5 digits; automatically widens past 99999
  const width = Math.max(5, String(nextSeq).length);
  const paddedSeq = String(nextSeq).padStart(width, '0');
  return prefix + '-' + year + '-' + paddedSeq;
}

/**
 * Prevents formula injection and sanitizes input strings
 */
function sanitizeInput(val) {
  if (val === undefined || val === null) return '';
  let str = String(val).trim();
  if (/^[=\+\-@]/.test(str)) {
    str = "'" + str;
  }
  return str;
}

/**
 * Formats Badge Numbers cleanly
 */
function formatBadgeNumber(val) {
  if (!val) return '';
  return String(val).trim();
}

/**
 * Standard Date Value Formatter (YYYY-MM-DD)
 */

/**
 * Formats a date value as m/d/yyyy (matches existing observation sheet style).
 */
function formatDateMDY(val) {
  if (!val && val !== 0) return '';
  let d = null;
  if (val instanceof Date) {
    d = val;
  } else {
    const s = String(val).trim();
    if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(s)) return s; // already m/d/yyyy
    if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
      d = new Date(s.substring(0, 10) + 'T00:00:00');
    } else {
      d = new Date(s);
    }
  }
  if (!d || isNaN(d.getTime())) return String(val);
  return (d.getMonth() + 1) + '/' + d.getDate() + '/' + d.getFullYear();
}

/**
 * Next sequential observation SN from max numeric value in column A (or row count).
 * Supports plain numbers (1073) and SO-YYYY-##### ids.
 */
function generateNextObservationSerial(sheet) {
  if (!sheet || sheet.getLastRow() <= 1) return 1;
  const numRows = sheet.getLastRow() - 1;
  const values = sheet.getRange(2, 1, numRows, 1).getValues();
  let maxSeq = 0;
  values.forEach(function (row) {
    const seq = parseRecordSerial(row[0]);
    if (seq !== null && seq > maxSeq) maxSeq = seq;
  });
  // Also never go below total data rows (handles gaps)
  if (numRows > maxSeq) maxSeq = numRows;
  return maxSeq + 1;
}

function formatDateValue(val) {
  if (!val && val !== 0) return '';
  if (val instanceof Date) {
    if (isNaN(val.getTime())) return '';
    const yyyy = val.getFullYear();
    const mm = String(val.getMonth() + 1).padStart(2, '0');
    const dd = String(val.getDate()).padStart(2, '0');
    return yyyy + '-' + mm + '-' + dd;
  }
  const str = String(val).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(str)) return str;
  // m/d/yyyy or mm/dd/yyyy
  const mdy = str.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (mdy) {
    const mm = String(parseInt(mdy[1], 10)).padStart(2, '0');
    const dd = String(parseInt(mdy[2], 10)).padStart(2, '0');
    return mdy[3] + '-' + mm + '-' + dd;
  }
  const d = new Date(str);
  if (!isNaN(d.getTime())) {
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const dd = String(d.getDate()).padStart(2, '0');
    return yyyy + '-' + mm + '-' + dd;
  }
  return str;
}

/**
 * Standard Timestamp Formatter (YYYY-MM-DD HH:MM:SS)
 */
function formatTimestamp(val) {
  if (!val) return '';
  let d = val instanceof Date ? val : new Date(val);
  if (isNaN(d.getTime())) return String(val);
  
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const hh = String(d.getHours()).padStart(2, '0');
  const min = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  
  return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
}

/**
 * Structured API Response Producer
 */
function createResponse(success, message, data, errorCode) {
  return {
    success: success,
    message: message || '',
    data: data || null,
    errorCode: errorCode || null,
    serverTimestamp: new Date().toISOString()
  };
}
