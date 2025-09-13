const { chromium } = require('playwright');

async function testBrowser() {
  console.log('Testing browser launch...');
  
  try {
    const browser = await chromium.launch({ 
      headless: false,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    console.log('Browser launched successfully!');
    
    const context = await browser.newContext();
    const page = await context.newPage();
    
    console.log('Page created successfully!');
    
    await page.goto('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    
    console.log('Navigated to rickroll URL!');
    
    // Keep browser open for 10 seconds
    await new Promise(resolve => setTimeout(resolve, 10000));
    
    await browser.close();
    console.log('Browser closed successfully!');
    
  } catch (error) {
    console.error('Error:', error);
  }
}

testBrowser();
