@echo off
echo 🧹 Cleaning up repository to remove large files...

echo.
echo 📊 Current repository size:
git count-objects -vH

echo.
echo 🗑️ Removing node_modules from Git tracking...
git rm -r --cached "dev/node_modules" 2>nul
if %errorlevel% neq 0 (
    echo ⚠️ node_modules not found in Git tracking
)

echo.
echo 🗑️ Removing large executable files from Git tracking...
git rm --cached "dev/*.exe" 2>nul
if %errorlevel% neq 0 (
    echo ⚠️ No .exe files found in Git tracking
)

echo.
echo 📝 Creating .gitignore to prevent future large files...
echo # Dependencies >> .gitignore
echo node_modules/ >> .gitignore
echo npm-debug.log* >> .gitignore
echo yarn-debug.log* >> .gitignore
echo yarn-error.log* >> .gitignore
echo. >> .gitignore
echo # Build outputs >> .gitignore
echo dist/ >> .gitignore
echo build/ >> .gitignore
echo *.exe >> .gitignore
echo *.dmg >> .gitignore
echo *.deb >> .gitignore
echo *.rpm >> .gitignore
echo. >> .gitignore
echo # OS files >> .gitignore
echo .DS_Store >> .gitignore
echo Thumbs.db >> .gitignore

echo.
echo 💾 Committing changes...
git add .gitignore
git commit -m "Remove large files and add .gitignore"

echo.
echo 📊 New repository size:
git count-objects -vH

echo.
echo ✅ Repository cleanup completed!
echo.
echo 🚀 Next steps:
echo 1. Push changes: git push origin main
echo 2. Use the portable package (72 KB) for releases
echo 3. The repository should now be under GitHub size limits
