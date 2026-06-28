# Repository Guidelines

## Project Structure & Module Organization
Solution `ITfoxtec.Identity.sln` contains the core library in `src/ITfoxtec.Identity.csproj` and xUnit tests in `test/ITfoxtec.Identity.UnitTest`. Keep NuGet package metadata in the library project file and keep release automation in `.github/workflows/release-nuget.yml`.

## Build, Test, and Development Commands
- `dotnet restore ITfoxtec.Identity.sln` - restore solution dependencies.
- `dotnet build ITfoxtec.Identity.sln -c Release` - build the multi-target library and tests.
- `dotnet test ITfoxtec.Identity.sln -c Release --no-build` - run the unit tests after a release build.
- `dotnet pack src/ITfoxtec.Identity.csproj -c Release` - create the NuGet package locally.

## Release / NuGet
- Releases are published through `.github/workflows/release-nuget.yml` when a GitHub Release is published.
- The GitHub release must target `main`; make sure `main` contains the release commit before publishing.
- The GitHub release tag must match `<Version>` in `src/ITfoxtec.Identity.csproj` exactly.
- `<AssemblyVersion>` and `<FileVersion>` must match `<Version>`.
- GitHub prerelease status must match the NuGet version: prereleases require a SemVer suffix such as `2.18.0-beta.1`; stable releases must not have a suffix.
- NuGet publishing uses Trusted Publishing through `NuGet/login@v1`; do not add a long-lived NuGet API key.
- The GitHub Actions secret `NUGET_USER` must contain the NuGet package owner name.
- NuGet packages cannot be overwritten. If a version has been published, bump the package version before preparing another release.
