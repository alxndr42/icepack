from pathlib import Path

import click

from icepack import IcepackReader, create_archive, extract_archive
from icepack.helper import Age, File, SSH
from icepack.meta import NAME, VERSION, SECRET_KEY, PUBLIC_KEY
from icepack.model import Compression


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
@click.option('--comment', help='Archive comment.')
@click.option(
    '--compression', '-c',
    help=f'Compression for all files. (Default: {Compression.GZ})',
    type=click.Choice([c.value for c in Compression]),
    default=Compression.GZ)
@click.option(
    '--mode',
    help='Store file/directory modes.',
    is_flag=True)
@click.option(
    '--mtime',
    help='Store file/directory modification times.',
    is_flag=True)
@click.option(
    '--recipient', '-r',
    help='Allow another public key/alias to extract.',
    multiple=True)
@click.pass_context
def create(ctx, src, dst, comment, compression, mode, mtime, recipient):
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
            comment=comment,
            compression=compression,
            mode=mode,
            mtime=mtime,
            recipients=recipient,
            log=click.echo)
    except Exception as e:
        raise click.ClickException(f'Archive creation failed: {e}')


@icepack.command()
@click.argument('src', type=click.Path(exists=True, dir_okay=False))
@click.argument('dst', type=click.Path(exists=True, file_okay=False))
@click.option(
    '--mode',
    help='Restore file/directory modes.',
    is_flag=True)
@click.option(
    '--mtime',
    help='Restore file/directory modification times.',
    is_flag=True)
@click.pass_context
def extract(ctx, src, dst, mode, mtime):
    """Extract files from an archive.

    SRC must be the archive file, DST must be a directory.
    """
    src_path = Path(src)
    dst_path = Path(dst)
    key_path = ctx.obj['config_path']
    _check_keys(key_path)
    try:
        extract_archive(
            src_path,
            dst_path,
            key_path,
            mode=mode,
            mtime=mtime,
            log=click.echo)
    except Exception as e:
        raise click.ClickException(f'Archive extraction failed: {e}')


@icepack.command(name='list')
@click.argument('src', type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def list_archive(ctx, src):
    """List the archive content."""
    src_path = Path(src).resolve()
    key_path = ctx.obj['config_path']
    _check_keys(key_path)
    try:
        with IcepackReader(src_path, key_path) as archive:
            if archive.metadata.comment:
                click.echo(f'Comment: {archive.metadata.comment}')
            for entry in archive.metadata.entries:
                click.echo(entry.name)
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


@icepack.group()
@click.pass_context
def signer(ctx):
    """Manage allowed signers."""
    pass


@signer.command(name='list')
@click.pass_context
def list_signers(ctx):
    """List allowed signers."""
    key_path = ctx.obj['config_path']
    own_path = key_path / PUBLIC_KEY
    own_key = own_path.read_text().strip()
    for key, alias in SSH.get_signers(key_path):
        if key == own_key:
            click.echo(f'{key} (Your Key)')
        elif alias:
            click.echo(f'{key} ({alias})')
        else:
            click.echo(f'{key}')


@signer.command()
@click.argument('key')
@click.option('--alias', '-a', help='Key alias.')
@click.pass_context
def add(ctx, key, alias):
    """Add an allowed signer."""
    key_path = ctx.obj['config_path']
    if not key.startswith('ssh-'):
        raise click.ClickException('Invalid key.')
    if alias and (' ' in alias or alias == NAME):
        raise click.ClickException('Invalid alias.')
    signers = SSH.get_signers(key_path)
    keys = {key for key, alias in signers}
    aliases = {alias for key, alias in signers if alias is not None}
    if key in keys:
        raise click.ClickException('Key already exists.')
    if alias in aliases:
        raise click.ClickException('Alias already exists.')
    SSH.update_signers(key_path, append=(key, alias))


@signer.command()
@click.argument('key_or_alias')
@click.pass_context
def remove(ctx, key_or_alias):
    """Remove an allowed signer."""
    key_path = ctx.obj['config_path']
    own_path = key_path / PUBLIC_KEY
    own_key = own_path.read_text().strip()
    if key_or_alias == own_key:
        raise click.ClickException('Cannot remove your own key.')
    signers = SSH.get_signers(key_path)
    keys = {key for key, alias in signers}
    aliases = {alias for key, alias in signers if alias is not None}
    if not (key_or_alias in keys or key_or_alias in aliases):
        raise click.ClickException('Key or alias not found.')
    SSH.update_signers(key_path, remove=key_or_alias)


def _check_keys(key_path):
    """Check if the keys have been initialized."""
    if not (key_path / SECRET_KEY).is_file():
        msg = f'Please run "{NAME} init" to initialize the keys.'
        raise click.ClickException(msg)


if __name__ == '__main__':
    icepack()
