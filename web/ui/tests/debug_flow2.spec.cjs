const { test } = require('@playwright/test')

// This test will create a zone and then click the Manage Records link for that zone and dump the page

test('debug flow create zone then open records', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.waitForSelector('text=Admin')
  await page.click('text=Admin')
  await page.click('text=Zones')

  await page.waitForSelector('input[placeholder="domain"]')
  const domain = `flow-${Date.now()}.test`
  await page.fill('input[placeholder="domain"]', domain)
  await page.click('text=Create Zone')
  await page.waitForSelector(`text=${domain}`)

  // find the row containing our domain and click its Manage Records link
  const row = await page.locator('tbody tr').filter({ hasText: domain }).first()
  const manage = row.locator('text=Manage Records')
  const href = await manage.getAttribute('href')
  console.log('MANAGE HREF:', href)
  await manage.click()
  await page.waitForTimeout(1000)
  const content = await page.content()
  console.log('AFTER CLICK HTML SNIPPET:', content.slice(0,500))
})