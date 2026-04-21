import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
var packageJsonPath = join(dirname(fileURLToPath(import.meta.url)), 'package.json');
var appVersion = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));
export default defineConfig({
    define: {
        'import.meta.env.VITE_APP_VERSION': JSON.stringify(appVersion.version),
    },
    plugins: [react()],
    server: {
        port: 5173
    },
    build: {
        rollupOptions: {
            input: {
                main: 'index.html',
                widget: 'widget.html',
                config: 'config.html'
            }
        }
    }
});
