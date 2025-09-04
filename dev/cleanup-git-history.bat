@echo off
echo 🧹 COMPLETE Git History Cleanup
echo ==============================

echo.
echo ⚠️ WARNING: This will permanently remove large files from Git history!
echo This will change all commit hashes and require a force push.
echo.
set /p confirm="Are you sure you want to continue? (y/N): "
if /i not "%confirm%"=="y" (
    echo ❌ Cancelled.
    exit /b 1
)

echo.
echo 📊 Current repository size:
git count-objects -vH

echo.
echo 💾 Creating backup branch...
git branch backup-before-cleanup

echo.
echo 🗑️ Removing large files from ALL commits...
echo This may take a while...

REM Remove electron.exe and other large files from all commits
git filter-branch --force --index-filter "git rm --cached --ignore-unmatch 'dev/node_modules/electron/dist/electron.exe' 'dev/node_modules/**/*.exe' 'dev/*.exe'" --prune-empty --tag-name-filter cat -- --all

echo.
echo 🧹 Cleaning up backup references...
for /f "tokens=*" %%i in ('git for-each-ref --format="%%(refname)" refs/original/') do git update-ref -d %%i

echo.
echo 🗜️ Running garbage collection...
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo.
echo 📊 New repository size:
git count-objects -vH

echo.
echo ✅ Git history cleanup completed!
echo.
echo 🚀 IMPORTANT: You need to force push to update GitHub:
echo    git push origin main --force
echo.
echo ⚠️ WARNING: This will permanently change the repository history.
echo Other collaborators will need to re-clone the repository.
