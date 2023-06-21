import { promisify } from 'node:util';
import { exec as execCallback } from 'node:child_process';

const exec = promisify(execCallback);

async function dockerExec(
  containerName: string,
  command: string
): Promise<{ stdout: string; stderr: string }> {
  return await exec(`docker exec -d ${containerName} ${command}`);
}

async function dockerSymlink(
  containerName: string,
  sourceDir: string,
  targetDir: string
): Promise<{ stdout: string; stderr: string }> {
  return await dockerExec(containerName, `ln -s ${sourceDir} ${targetDir}`);
}

async function dockerDeleteDir(
  containerName: string,
  dir: string
): Promise<{ stdout: string; stderr: string }> {
  return await dockerExec(containerName, `rm -rf ${dir}`);
}

async function nginxReload(
  containerName: string
): Promise<{ stdout: string; stderr: string }> {
  return await dockerExec(containerName, `nginx -s reload`);
}

export async function deployServiceWorker(srcDir: string, targetDir: string) {
  console.log(`Deleting target folder (${targetDir})...`);
  await dockerDeleteDir('sw-reverse-proxy', targetDir);

  console.log(
    `Linking new source folder (${srcDir}) to target folder (${targetDir})...`
  );
  await dockerSymlink('sw-reverse-proxy', srcDir, targetDir);

  console.log('Reloading nginx config...');
  await nginxReload('sw-reverse-proxy');
}
