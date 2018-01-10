set GIT_BRANCH=unavailable
set GIT_COMMIT=unavailable

for /f "delims=" %%a in ('git rev-parse --verify HEAD') do set GIT_COMMIT=%%a
for /f "delims=" %%a in ('git rev-parse --abbrev-ref HEAD') do set GIT_BRANCH=%%a

echo ^<?xml version="1.0" encoding="utf-8"?^>> GitInfoPropertySheet.props
echo ^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^>>> GitInfoPropertySheet.props
echo   ^<ImportGroup Label="PropertySheets" /^>>> GitInfoPropertySheet.props
echo   ^<PropertyGroup Label="UserMacros"^>>> GitInfoPropertySheet.props
echo     ^<GitCommit^>%GIT_COMMIT%^</GitCommit^>>> GitInfoPropertySheet.props
echo     ^<GitBranch^>%GIT_BRANCH%^</GitBranch^>>> GitInfoPropertySheet.props
echo   ^</PropertyGroup^>>> GitInfoPropertySheet.props
echo   ^<PropertyGroup /^>>> GitInfoPropertySheet.props
echo   ^<ItemDefinitionGroup /^>>> GitInfoPropertySheet.props
echo   ^<ItemGroup /^>>> GitInfoPropertySheet.props
echo ^</Project^>>> GitInfoPropertySheet.props