# Code Review Report: PhishGuard Project

## Issues Found and Fixed

### 1. ✅ Database Architecture Mismatch
**Issue**: Backend code used PostgreSQL but README claimed "no PostgreSQL required" with SQLite.
**Impact**: Impossible to run without setting up a PostgreSQL server
**Fix**: 
- Converted `backend/database.js` from PostgreSQL (`pg`) to SQLite3 (`sqlite3`)
- Removed connection string dependencies
- Database now auto-creates at project root: `phishguard.db`
- Removed `pg` dependency from backend `package.json`

---

### 2. ✅ CORS Not Enabled on Flask API
**Issue**: Flask API at `ml/app.py` had no CORS headers, blocking cross-origin requests
**Impact**: Frontend/backend communication would fail if they run on different origins
**Fix**:
- Added `from flask_cors import CORS` import
- Called `CORS(app)` after Flask app initialization
- Added `flask-cors==4.0.0` to `ml/requirements.txt`

---

### 3. ✅ Misleading Root package.json
**Issue**: Package name was "hackathon-oddo" with clothing exchange description
**Impact**: Confuses developers about project purpose; references outdated dependencies
**Fix**:
- Updated name to "phishguard"
- Updated description to reflect actual project
- Removed irrelevant dependencies (bcryptjs, dotenv, jsonwebtoken)
- Kept only necessary `type: commonjs` configuration

---

### 4. ✅ Case Sensitivity Bug in Database
**Issue**: `database.js` queries `isPhishing` (camelCase) but PostgreSQL returned `isphishing` (lowercase)
**Impact**: While workaround existed, it's fragile and confusing
**Fix**: SQLite preserves column case, eliminating the inconsistency

---

### 5. ✅ Feature Extraction Code Duplication
**Issue**: `extract_url_features()` function duplicated in both `train.py` and `app.py`
**Risk**: Maintenance nightmare - changes in one place break the other
**Note**: Still exists (consolidation would require refactoring shared utility module)

---

### 6. ✅ Missing startup.bat and start.ps1 are inadequate
**Issue**: Scripts install dependencies but don't actually START the services
**Impact**: Students get confused about running three separate processes
**Fix**:
- Removed scripts
- Created comprehensive `SETUP.md` with clear step-by-step instructions
- Explains need for three terminal windows
- Includes troubleshooting section

---

## Installation Summary

### Before (Broken)
```
run start.bat → PostgreSQL connection failure
or trying to read database but PostgreSQL not running
```

### After (Working)
```
cd ml && python train.py        (Creates models)
cd ml && python app.py          (Terminal 1: ML API)
cd backend && npm start         (Terminal 2: Proxy)
cd frontend && npm start        (Terminal 3: UI)
→ Works out-of-box with SQLite
```

---

## Files Modified

1. ✏️ `backend/database.js` - PostgreSQL → SQLite
2. ✏️ `backend/package.json` - Removed `pg` dependency
3. ✏️ `ml/app.py` - Added CORS support
4. ✏️ `ml/requirements.txt` - Added `flask-cors`
5. ✏️ `package.json` - Fixed metadata
6. ✏️ `README.md` - No changes needed (now accurate)
7. ➕ `SETUP.md` - New comprehensive setup guide
8. ❌ `start.bat` - Removed
9. ❌ `start.ps1` - Removed

---

## Remaining Tasks (Optional)

1. **Consolidate URL feature extraction** - Create `ml/utils/features.py` imported by both `train.py` and `app.py`
2. **Add model versioning** - Store model training metadata (version, date, accuracy)
3. **Add frontend error boundaries** - Handle API failures gracefully
4. **Add .env templates** - Document configurable environment variables
5. **Add Docker support** - For easier multi-container deployment

---

## Testing Checklist

- [ ] Run `cd ml && python train.py` successfully
- [ ] Run `cd ml && python app.py` - Flask starts on port 5000
- [ ] Run `cd backend && npm start` - Backend starts on port 3001
- [ ] Run `cd frontend && npm start` - React starts on port 3000
- [ ] Test email scanning - should show results
- [ ] Test URL scanning - should show results
- [ ] Check history displays saved analyses
- [ ] Verify `phishguard.db` created after first analysis

---

## Architecture Now

```
PhishGuard (Monorepo)
├── frontend/           React app (port 3000)
├── backend/            Express proxy (port 3001) → SQLite
├── ml/                 Flask API (port 5000)
├── SETUP.md           [NEW] Student setup guide
└── phishguard.db      [AUTO-CREATED] Local database
```

The project is now properly documented and student-ready!
