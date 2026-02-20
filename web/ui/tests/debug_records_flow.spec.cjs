const { test } = require('@playwright/test')

test('debug records flow: token and API after navigation', async ({ page, request }) => {
  const res = await request.post('http://localhost:8080/api/v1/auth/login', { data: { username: 'admin', password: 'admin123' } })
  const body = await res.json()
  const token = body.token
  await page.addInitScript(token => { localStorage.setItem('token', token) }, token)

  await page.goto('http://localhost:3000/')
  await page.click('text=Admin')
  await page.click('text=Zones')

  await page.waitForSelector('input[placeholder="domain"]')
  const domain = `flow2-${Date.now()}.test`
  await page.fill('input[placeholder="domain"]', domain)
  await page.click('text=Create Zone')
  await page.waitForSelector(`text=${domain}`)

  const row = await page.locator('tbody tr').filter({ hasText: domain }).first()
  const manage = row.locator('text=Manage Records')
  const href = await manage.getAttribute('href')
  console.log('MANAGE HREF:', href)

  // navigate to href and inspect
  await page.goto('http://localhost:3000' + href)
  await page.waitForTimeout(500)
  console.log('PAGE URL:', page.url())
  const lsToken = await page.evaluate(() => localStorage.getItem('token'))
  console.log('localStorage token present?', !!lsToken)

  // try fetching records from page context
  const fetchResult = await page.evaluate(async (zoneId) => {
    try {
      const r = await fetch(`/api/v1/zones/${zoneId}/records`, { method: 'GET', headers: { 'Content-Type': 'application/json' } })
      const text = await r.text()
      return { status: r.status, ok: r.ok, text: text.slice(0,200) }
    } catch (e) { return { error: e.message } }
  }, href.split('/')[3])

  console.log('FETCH RESULT:', fetchResult)
})
