import { spawn } from 'child_process';
import { promisify } from 'util';

async function launchSystemBrowser() {
  console.log('Launching system Chrome browser...');
  
  try {
    // Try to launch Chrome directly
    const chromePaths = [
      'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
      'chrome',
      'google-chrome'
    ];
    
    let chromePath = null;
    for (const path of chromePaths) {
      try {
        // Try to launch Chrome with the rickroll URL
        const args = ['https://www.youtube.com/watch?v=dQw4w9WgXcQ'];
        
        console.log(`Trying to launch: ${path}`);
        
        const child = spawn(path, args, {
          stdio: 'pipe',
          detached: true
        });
        
        child.on('error', (error) => {
          console.log(`Failed to launch ${path}: ${error.message}`);
        });
        
        child.on('spawn', () => {
          console.log(`Successfully launched Chrome with ${path}!`);
          chromePath = path;
        });
        
        // Wait a bit to see if it spawns
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        if (chromePath) break;
        
      } catch (error) {
        console.log(`Error with ${path}: ${error.message}`);
      }
    }
    
    if (!chromePath) {
      console.log('Could not launch Chrome, trying system default...');
      // Try system default browser
      const { exec } = await import('child_process');
      const execAsync = promisify(exec);
      
      try {
        await execAsync('start https://www.youtube.com/watch?v=dQw4w9WgXcQ');
        console.log('Launched system default browser!');
      } catch (error) {
        console.error('Failed to launch system browser:', error);
      }
    }
    
  } catch (error) {
    console.error('Error launching browser:', error);
  }
}

launchSystemBrowser();
