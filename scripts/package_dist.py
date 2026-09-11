#!/usr/bin/env python3
"""Package the validated binary release without rebuilding or changing its JARs."""

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.3.4'
NAME = 'securitycontext-' + VERSION
VALIDATION = ROOT / 'build/validation/dist-20260911/java/artifacts.json'
AGENT_SHA256 = 'bbf83c151b6400709e2f225bdd07a04f839d9d13b8b93464241333fd25d3e3ba'
EPOCH = int(os.environ.get('SOURCE_DATE_EPOCH', '1789084800'))


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def copy(source, destination):
    if not source.is_file() or source.is_symlink():
        raise ValueError('Missing or non-regular release input: ' + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def checked_copy(source, destination, expected):
    copy(source, destination)
    if digest(destination) != expected:
        raise ValueError('Artifact differs from the validated release: ' + str(source))
    if destination.suffix == '.jar':
        with zipfile.ZipFile(destination) as archive:
            classes = [name for name in archive.namelist() if name.endswith('.class')]
            duplicate_extension = source.name == 'securitycontext.jar' and len(classes) != len(set(classes))
            if duplicate_extension or any(re.search(r' \d+(?:/|\.class$)', name) for name in classes):
                raise ValueError('Duplicate class output; rebuild from clean generated directories: ' + str(source))


def license_resources(data, label, package, inventory, nested=False):
    files = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for entry in sorted(archive.namelist()):
            parts = PurePosixPath(entry)
            if parts.is_absolute() or '..' in parts.parts:
                raise ValueError('Unsafe archive entry: ' + entry)
            filename = parts.name.lower()
            if (not entry.endswith(('/', '.class'))
                    and any(term in filename for term in ('license', 'notice', 'copying', 'copyright'))):
                target = package / 'licenses' / label / entry
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))
                files.append(target.relative_to(package).as_posix())
            if nested and entry.startswith('BOOT-INF/lib/') and entry.endswith('.jar'):
                license_resources(archive.read(entry), label + '/dependencies/' + parts.name,
                                  package, inventory)
    inventory.append({'artifact': label, 'artifact_sha256': hashlib.sha256(data).hexdigest(),
                      'embedded_notice_files': files,
                      'status': 'extracted' if files else 'no_embedded_notice_found'})


def payload_files(directory):
    return sorted(path for path in directory.rglob('*') if path.is_file())


def archives(package, temporary):
    files = payload_files(package)
    tar_path = temporary / (NAME + '.tar.gz')
    with tar_path.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for path in files:
                    info = archive.gettarinfo(str(path), NAME + '/' + path.relative_to(package).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ''
                    info.mtime = EPOCH
                    info.pax_headers = {}
                    with path.open('rb') as stream:
                        archive.addfile(info, stream)
    zip_path = temporary / (NAME + '.zip')
    timestamp = dt.datetime.fromtimestamp(max(EPOCH, 315532800), dt.timezone.utc).timetuple()[:6]
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            info = zipfile.ZipInfo(NAME + '/' + path.relative_to(package).as_posix(), timestamp)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | stat.S_IMODE(path.stat().st_mode)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    return [tar_path, zip_path]


def build(destination, replace):
    version_match = re.search(r'version\s*=\s*"([^"]+)"', (ROOT / 'build.gradle.kts').read_text())
    baseline = json.loads(VALIDATION.read_text())
    if not version_match or version_match.group(1) != VERSION or baseline['version'] != VERSION:
        raise ValueError('Build version and validated release version must match')
    expected_matrix = ['Boot2/Java8', 'Boot2/Java11', 'Boot3/Java17', 'Boot3/Java21']
    if sorted(baseline['verified_matrix']) != sorted(expected_matrix):
        raise ValueError('This release requires the four-JVM matrix on the validated artifacts')
    destination.mkdir(parents=True, exist_ok=True)
    final = destination / NAME
    if final.exists():
        if not replace or not (final / 'manifest.json').is_file():
            raise ValueError('Existing release directory; use --replace only for a generated release')
        if json.loads((final / 'manifest.json').read_text()).get('distribution') != NAME:
            raise ValueError('Refusing to replace a directory with a different manifest')

    with tempfile.TemporaryDirectory(prefix='.package-', dir=destination) as temporary_name:
        temporary = Path(temporary_name)
        package = temporary / NAME
        package.mkdir()
        for path in payload_files(ROOT / 'release'):
            if path.name != '.DS_Store' and not re.search(r' \d+\.', path.name):
                copy(path, package / path.relative_to(ROOT / 'release'))
        required_docs = ['README.zh-CN.md', 'README.en.md', 'RELEASE_NOTES.zh-CN.md',
                         'RELEASE_NOTES.en.md', 'docs/guide.zh-CN.md', 'docs/guide.en.md',
                         'bin/run-demo.sh', 'licenses/opentelemetry-javaagent/LICENSE']
        for name in required_docs:
            if not (package / name).is_file():
                raise ValueError('Missing release documentation: ' + name)
        copy(package / 'README.en.md', package / 'README.md')
        copy(ROOT / 'scripts/securityctl.py', package / 'bin/securityctl.py')
        validation = VALIDATION.with_name('validation.json')
        if json.loads(validation.read_text()).get('version') != VERSION:
            raise ValueError('Validation summary must describe this release')
        copy(validation, package / 'validation.json')

        inputs = []
        for artifact in baseline['artifacts']:
            source = ROOT / artifact['path']
            folder = 'lib' if source.name == 'securitycontext.jar' else 'examples/apps'
            target = package / folder / source.name
            checked_copy(source, target, artifact['sha256'])
            inputs.append(target)
        agent = package / 'lib/opentelemetry-javaagent-2.31.1.jar'
        checked_copy(ROOT / 'build/deps' / agent.name, agent, AGENT_SHA256)
        inputs.append(agent)
        for name in ['otel-collector-config.yaml', 'otel-collector-persistent.yaml',
                     'docker-compose.collector.yml', 'docker-compose.persistent.yml']:
            copy(ROOT / 'deploy' / name, package / 'collector' / name)

        fixture = ROOT / baseline['example_fixture']
        for name in ['application.cdx.json', 'verification.json']:
            copy(fixture / name, package / 'examples/observed' / name)
        evidence = [json.loads(line) for line in (fixture / 'evidence.jsonl').read_text().splitlines() if line.strip()]
        representative = next(record for record in evidence if record.get('event_name') == 'security.dataflow.observed')
        (package / 'examples/observed/evidence.jsonl').write_text(
            json.dumps(representative, ensure_ascii=False) + '\n', encoding='utf-8')

        inventory = []
        for artifact in inputs:
            license_resources(artifact.read_bytes(), artifact.name, package, inventory,
                              nested=artifact.parent.name == 'apps')
        cache = ROOT / 'build/validation/gradle-home/caches/modules-2/files-2.1/com.fasterxml.jackson.core'
        for name in ['jackson-annotations', 'jackson-core', 'jackson-databind']:
            matches = sorted((cache / name / '2.19.2').glob('*/*.jar'))
            if len(matches) != 1:
                raise ValueError('Expected one original Jackson dependency for notice preservation: ' + name)
            license_resources(matches[0].read_bytes(), matches[0].name, package, inventory)
        write_json(package / 'licenses/inventory.json', inventory)

        for path in payload_files(package):
            path.chmod(0o755 if path.parent == package / 'bin' else 0o644)
        manifest = {
            'schema_version': 1, 'distribution': NAME, 'version': VERSION,
            'source': 'security_context',
            'release_kind': 'prototype_binary_distribution',
            'archive_timestamp': dt.datetime.fromtimestamp(EPOCH, dt.timezone.utc).isoformat(),
            'build_source': {'state': 'uncommitted_workspace', 'commit': None,
                       'binaries': 'unchanged_validated_release_inputs'},
            'compatibility': {'otel_javaagent': '2.31.1', 'extension_api': '2.31.1-alpha',
                              'otel_sdk': '1.65.0', 'extension_java_target': 8,
                              'verified_matrix': baseline['verified_matrix']},
            'example_origin': {'type': 'controlled_demo_fixture', 'result': 'not_a_general_security_assurance'},
            'files': [{'path': path.relative_to(package).as_posix(), 'bytes': path.stat().st_size,
                       'sha256': digest(path), 'mode': oct(stat.S_IMODE(path.stat().st_mode))}
                      for path in payload_files(package)]
        }
        write_json(package / 'manifest.json', manifest)
        (package / 'SHA256SUMS').write_text(''.join(
            digest(path) + '  ' + path.relative_to(package).as_posix() + '\n'
            for path in payload_files(package)), encoding='utf-8')
        built_archives = archives(package, temporary)
        standalone = temporary / ('securitycontext-' + VERSION + '.jar')
        copy(package / 'lib/securitycontext.jar', standalone)
        deliverables = built_archives + [standalone]
        checksums = ''.join(digest(path) + '  ' + path.name + '\n' for path in deliverables)
        if final.exists():
            shutil.rmtree(final)
        os.replace(package, final)
        for path in deliverables:
            os.replace(path, destination / path.name)
        checksum_file = temporary / 'SHA256SUMS'
        checksum_file.write_text(checksums, encoding='utf-8')
        os.replace(checksum_file, destination / 'SHA256SUMS')
        (destination / (NAME + '.SHA256SUMS')).write_text(checksums, encoding='utf-8')
        print(json.dumps({'source': 'security_context', 'directory': str(final), 'archives': [str(destination / path.name) for path in built_archives],
                          'standalone_extension': str(destination / standalone.name),
                          'checksums': checksums}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--replace', action='store_true', help='replace only this version of a generated release')
    args = parser.parse_args()
    try:
        build(args.output.resolve(), args.replace)
    except (OSError, ValueError, KeyError, StopIteration, zipfile.BadZipFile) as error:
        parser.exit(2, str(error) + '\n')
