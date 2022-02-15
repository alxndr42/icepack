from pathlib import Path

import click

from icepack import create_archive, extract_archive
from icepack.helper import Age, SSH
from icepack.meta import NAME, VERSION, SECRET_KEY


@click.group()
@click.option(
    '--config', '-c',
    help='Configuration directory.',
    type=click.Path(file_okay=False))
@click.pass_context
def icepack(ctx, config):
    """Encrypting File Archiver"""
    ctx.obj = {}
    if config is None:
        config_path = Path(click.get_app_dir(NAME))
    else:
        config_path = Path(config)
    config_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    ctx.obj['config_path'] = config_path


@icepack.command()
@click.pass_context
def init(ctx):
    """Initialize the keys."""
    key_path = ctx.obj['config_path']
    secret_key = key_path / SECRET_KEY
    if secret_key.is_file():
        raise click.ClickException(f'{secret_key} already exists.')
    try:
        SSH.keygen(key_path)
    except Exception:
        raise click.ClickException('Failed to initialize the keys.')
    click.echo(f'The keys have been initialized in {key_path}')
    click.echo('Make sure to protect and backup this directory!')


@icepack.command()
@click.argument('src', type=click.Path(exists=True))
@click.argument('dst', type=click.Path())
@click.option(
    '--recipient', '-r',
    help='Allow another recipient to extract the archive.',
    multiple=True)
@click.pass_context
def create(ctx, src, dst, recipient):
    """Store files in an archive.

    SRC must be a file or directory, DST must be the archive file.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    key_path = ctx.obj['config_path']
    _check_keys(key_path)
    try:
        create_archive(
            src_path,
            dst_path,
            key_path,
            extra_recipients=recipient,
            log=click.echo)
    except Exception as e:
        raise click.ClickException(f'Archive creation failed: {e}')


@icepack.command()
@click.argument('src', type=click.Path(exists=True, dir_okay=False))
@click.argument('dst', type=click.Path(exists=True, file_okay=False))
@click.pass_context
def extract(ctx, src, dst):
    """Extract files from an archive.

    SRC must be the archive file, DST must be a directory.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    key_path = ctx.obj['config_path']
    _check_keys(key_path)
    try:
        extract_archive(src_path, dst_path, key_path, log=click.echo)
    except Exception as e:
        raise click.ClickException(f'Archive extraction failed: {e}')


@icepack.command()
@click.argument('src', type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def list(ctx, src):
    """List the archive content."""
    src_path = Path(src)
    key_path = ctx.obj['config_path']
    _check_keys(key_path)
    try:
        extract_archive(src_path, None, key_path, log=click.echo)
    except Exception as e:
        raise click.ClickException(f'Archive listing failed: {e}')


@icepack.command()
@click.option(
    '--dependencies', '-d',
    help='Check the dependencies.',
    is_flag=True)
@click.pass_context
def version(ctx, dependencies):
    """Show the version information."""
    click.echo(f'{NAME} {VERSION}')
    if not dependencies:
        return
    age_version, age_keygen = Age.version()
    if age_version:
        click.echo(f'✅ age found. (Version: {age_version})')
    else:
        click.echo(f'❌ age not found.')
    if age_keygen:
        click.echo(f'✅ age-keygen found.')
    else:
        click.echo(f'❌ age-keygen not found.')
    ssh_version, ssh_keygen = SSH.version()
    if ssh_version:
        click.echo(f'✅ ssh found. (Version: {ssh_version})')
    else:
        click.echo(f'❌ ssh not found.')
    if ssh_keygen:
        click.echo(f'✅ ssh-keygen found.')
    else:
        click.echo(f'❌ ssh-keygen not found.')


def _check_keys(key_path):
    """Check if the keys have been initialized."""
    if not (key_path / SECRET_KEY).is_file():
        msg = f'Please run "{NAME} init" to initialize the keys.'
        raise click.ClickException(msg)


if __name__ == '__main__':
    icepack()
