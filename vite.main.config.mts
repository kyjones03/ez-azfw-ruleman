import { defineConfig } from 'vite';
import { rheaStrict } from './vite.rhea.plugin';

// https://vitejs.dev/config
export default defineConfig({
  plugins: [rheaStrict()],
});
