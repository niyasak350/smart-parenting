require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_DAYS = Math.max(1, Number(process.env.SESSION_DAYS || 7));
const COOKIE_NAME = 'spa_session';

app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname)));

const SYSTEM_PROMPT = `You are Smart Parenting Assistant, a friendly general parenting guidance assistant. Give short, practical, easy-to-understand advice for parents and caregivers. You may discuss routines, nutrition basics, sleep habits, activities, emotions, child development, and mother wellness in general terms. Do not diagnose medical conditions, prescribe medicines, give medication doses, or replace a pediatrician or other qualified clinician. If a message suggests an emergency, serious symptoms, self-harm, danger to a child, severe postpartum mental-health symptoms, or another urgent situation, clearly advise contacting local emergency services or an appropriate healthcare professional immediately. Never claim certainty about a medical condition. Respect privacy and do not ask for unnecessary sensitive information.`;

function passwordHash(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const [salt, key] = String(stored).split(':');
    if (!salt || !key) return resolve(false);
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      const a = Buffer.from(key, 'hex');
      const b = Buffer.from(derivedKey.toString('hex'), 'hex');
      resolve(a.length === b.length && crypto.timingSafeEqual(a, b));
    });
  });
}
const tokenHash = token => crypto.createHash('sha256').update(token).digest('hex');
function getCookie(req, name) {
  const header = req.headers.cookie || '';
  const found = header.split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.slice(name.length + 1)) : null;
}
async function createSession(parentId, res) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 86400000);
  await db.execute('INSERT INTO sessions (token_hash,parent_id,expires_at) VALUES (?,?,?)', [tokenHash(token), parentId, expires]);
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);
}
async function currentUser(req) {
  const token = getCookie(req, COOKIE_NAME);
  if (!token) return null;
  const [rows] = await db.execute(`SELECT p.id,p.name,p.email,c.id AS child_id,c.name AS child_name,c.birth_date,c.allergies
    FROM sessions s JOIN parents p ON p.id=s.parent_id LEFT JOIN children c ON c.parent_id=p.id
    WHERE s.token_hash=? AND s.expires_at>NOW() LIMIT 1`, [tokenHash(token)]);
  return rows[0] || null;
}
async function requireAuth(req, res, next) {
  try {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'Please login first.' });
    req.user = user;
    next();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Could not check your login session.' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, childName, birthDate } = req.body || {};
  if (!name || !email || !password || !childName) return res.status(400).json({ error: 'Parent name, email, password and child name are required.' });
  if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const cleanEmail = String(email).trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(cleanEmail)) return res.status(400).json({ error: 'Please enter a valid email address.' });
  try {
    const stored = await passwordHash(String(password));
    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();
      const [existing] = await conn.execute('SELECT id FROM parents WHERE email=? LIMIT 1', [cleanEmail]);
      if (existing.length) { await conn.rollback(); return res.status(409).json({ error: 'An account with this email already exists.' }); }
      const [parent] = await conn.execute('INSERT INTO parents(name,email,password_hash) VALUES(?,?,?)', [String(name).trim(), cleanEmail, stored]);
      const [child] = await conn.execute('INSERT INTO children(parent_id,name,birth_date) VALUES(?,?,?)', [parent.insertId, String(childName).trim(), birthDate || null]);
      await conn.execute('INSERT INTO nutrition_preferences(child_id) VALUES(?)', [child.insertId]);
      await conn.commit();
      await createSession(parent.insertId, res);
      res.status(201).json({ message: 'Account created.' });
    } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not create the account. Check your MySQL setup.' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  try {
    const [rows] = await db.execute('SELECT id,password_hash FROM parents WHERE email=? LIMIT 1', [String(email).trim().toLowerCase()]);
    if (!rows.length || !(await verifyPassword(String(password), rows[0].password_hash))) return res.status(401).json({ error: 'Incorrect email or password.' });
    await createSession(rows[0].id, res);
    res.json({ message: 'Logged in.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not login. Check your MySQL setup.' }); }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const token = getCookie(req, COOKIE_NAME);
    if (token) await db.execute('DELETE FROM sessions WHERE token_hash=?', [tokenHash(token)]);
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    res.json({ message: 'Logged out.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not logout.' }); }
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'Not logged in.' });
    res.json({ parent: { id: user.id, name: user.name, email: user.email }, child: { id: user.child_id, name: user.child_name, birthDate: user.birth_date, allergies: user.allergies } });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load profile.' }); }
});

app.put('/api/profile/child', requireAuth, async (req, res) => {
  const { name, birthDate, allergies } = req.body || {};
  if (!name || !req.user.child_id) return res.status(400).json({ error: 'Child name is required.' });
  try {
    await db.execute('UPDATE children SET name=?,birth_date=?,allergies=? WHERE id=? AND parent_id=?', [String(name).trim(), birthDate || null, allergies || null, req.user.child_id, req.user.id]);
    res.json({ message: 'Child profile updated.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not update child profile.' }); }
});

app.post('/api/profile/growth', requireAuth, async (req, res) => {
  const { heightCm, weightKg, recordedOn } = req.body || {};
  const h = Number(heightCm), w = Number(weightKg);
  if (!req.user.child_id || !Number.isFinite(h) || h <= 0 || h > 250 || !Number.isFinite(w) || w <= 0 || w > 300) return res.status(400).json({ error: 'Enter valid height and weight.' });
  try {
    await db.execute('INSERT INTO growth_records(child_id,height_cm,weight_kg,recorded_on) VALUES(?,?,?,COALESCE(?,CURDATE()))', [req.user.child_id, h, w, recordedOn || null]);
    res.json({ message: 'Growth record saved.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not save growth record.' }); }
});
app.get('/api/profile/growth', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT height_cm AS heightCm,weight_kg AS weightKg,recorded_on AS recordedOn FROM growth_records WHERE child_id=? ORDER BY recorded_on DESC,id DESC LIMIT 1', [req.user.child_id]);
    res.json({ growth: rows[0] || null });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load growth data.' }); }
});

app.post('/api/profile/mood', requireAuth, async (req, res) => {
  const { mood, note, recordedOn } = req.body || {};
  const allowed = ['Happy', 'Calm', 'Okay', 'Sad', 'Upset'];
  if (!allowed.includes(mood)) return res.status(400).json({ error: 'Choose a valid mood.' });
  try {
    await db.execute('INSERT INTO mood_records(child_id,mood,recorded_on,note) VALUES(?,?,COALESCE(?,CURDATE()),?)', [req.user.child_id, mood, recordedOn || null, note || null]);
    res.json({ message: 'Mood saved.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not save mood.' }); }
});
app.get('/api/profile/mood', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT mood,note,recorded_on AS recordedOn FROM mood_records WHERE child_id=? ORDER BY recorded_on DESC,id DESC LIMIT 1', [req.user.child_id]);
    res.json({ mood: rows[0] || null });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load mood.' }); }
});

app.get('/api/profile/nutrition', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT age_group AS ageGroup,food_preference AS foodPreference,foods_to_avoid AS foodsToAvoid,water_goal AS waterGoal FROM nutrition_preferences WHERE child_id=? LIMIT 1', [req.user.child_id]);
    res.json({ preferences: rows[0] || null });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load nutrition preferences.' }); }
});
app.put('/api/profile/nutrition', requireAuth, async (req, res) => {
  const { ageGroup, foodPreference, foodsToAvoid, waterGoal } = req.body || {};
  const allowedAge = ['toddler', 'preschool', 'school', 'teen', ''];
  const allowedPref = ['All foods', 'Vegetarian', 'Egg-friendly', 'Non-vegetarian', ''];
  const goal = waterGoal === '' || waterGoal == null ? null : Number(waterGoal);
  if (!allowedAge.includes(String(ageGroup || '')) || !allowedPref.includes(String(foodPreference || '')) || (goal !== null && (!Number.isInteger(goal) || goal < 1 || goal > 20))) return res.status(400).json({ error: 'Please enter valid nutrition preferences.' });
  try {
    await db.execute(`INSERT INTO nutrition_preferences(child_id,age_group,food_preference,foods_to_avoid,water_goal) VALUES(?,?,?,?,?)
      ON DUPLICATE KEY UPDATE age_group=VALUES(age_group),food_preference=VALUES(food_preference),foods_to_avoid=VALUES(foods_to_avoid),water_goal=VALUES(water_goal)`, [req.user.child_id, ageGroup || null, foodPreference || null, foodsToAvoid || null, goal]);
    res.json({ message: 'Nutrition preferences saved.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not save nutrition preferences.' }); }
});

app.get('/api/profile/vaccinations', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT id,vaccine_name AS vaccineName,due_date AS dueDate,status,notes FROM vaccinations WHERE child_id=? ORDER BY due_date IS NULL,due_date,id', [req.user.child_id]);
    res.json({ vaccinations: rows });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load vaccinations.' }); }
});
app.post('/api/profile/vaccinations', requireAuth, async (req, res) => {
  const { vaccineName, dueDate, notes } = req.body || {};
  if (!String(vaccineName || '').trim()) return res.status(400).json({ error: 'Vaccine name is required.' });
  try {
    await db.execute('INSERT INTO vaccinations(child_id,vaccine_name,due_date,status,notes) VALUES(?,?,?,\'planned\',?)', [req.user.child_id, String(vaccineName).trim(), dueDate || null, notes || null]);
    res.json({ message: 'Vaccination saved.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not save vaccination.' }); }
});

app.get('/api/profile/wellness', requireAuth, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT mood,sleep_hours AS sleepHours,water_glasses AS waterGlasses,self_care_count AS selfCareCount,note,record_date AS recordDate FROM mother_wellness WHERE parent_id=? ORDER BY record_date DESC LIMIT 1', [req.user.id]);
    res.json({ wellness: rows[0] || null });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not load wellness data.' }); }
});
app.put('/api/profile/wellness', requireAuth, async (req, res) => {
  const { mood, sleepHours, waterGlasses, selfCareCount, note, recordDate } = req.body || {};
  const sleep = sleepHours === '' || sleepHours == null ? null : Number(sleepHours);
  const water = waterGlasses === '' || waterGlasses == null ? null : Number(waterGlasses);
  const selfCare = selfCareCount === '' || selfCareCount == null ? null : Number(selfCareCount);
  if (sleep !== null && (!Number.isFinite(sleep) || sleep < 0 || sleep > 24)) return res.status(400).json({ error: 'Enter valid sleep hours.' });
  if (water !== null && (!Number.isInteger(water) || water < 0 || water > 50)) return res.status(400).json({ error: 'Enter valid water glasses.' });
  if (selfCare !== null && (!Number.isInteger(selfCare) || selfCare < 0 || selfCare > 50)) return res.status(400).json({ error: 'Enter valid self-care count.' });
  try {
    await db.execute(`INSERT INTO mother_wellness(parent_id,record_date,mood,sleep_hours,water_glasses,self_care_count,note)
      VALUES(?,COALESCE(?,CURDATE()),?,?,?,?,?)
      ON DUPLICATE KEY UPDATE mood=VALUES(mood),sleep_hours=VALUES(sleep_hours),water_glasses=VALUES(water_glasses),self_care_count=VALUES(self_care_count),note=VALUES(note)`, [req.user.id, recordDate || null, mood || null, sleep, water, selfCare, note || null]);
    res.json({ message: 'Wellness check-in saved.' });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Could not save wellness data.' }); }
});

app.post('/api/chat', async (req, res) => {
  try {
    const { message, childAge } = req.body || {};
    if (!message || typeof message !== 'string' || !message.trim()) return res.status(400).json({ error: 'Please enter a question.' });
    if (!process.env.OPENAI_API_KEY) return res.status(503).json({ error: 'AI service is not configured yet. Add OPENAI_API_KEY on the server.' });
    let context = childAge ? `The child age provided by the parent is ${childAge}.` : '';
    const user = await currentUser(req);
    if (user && user.birth_date) {
      const dob = new Date(user.birth_date), today = new Date();
      let years = today.getFullYear() - dob.getFullYear();
      if (today.getMonth() < dob.getMonth() || (today.getMonth() === dob.getMonth() && today.getDate() < dob.getDate())) years--;
      if (years >= 0) context = `The logged-in child's age is approximately ${years} years. Use this only when relevant.`;
    }
    const response = await fetch('https://api.openai.com/v1/responses', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` }, body: JSON.stringify({ model: process.env.OPENAI_MODEL || 'gpt-5-mini', instructions: SYSTEM_PROMPT, input: `${context}\nParent question: ${message.trim()}`, max_output_tokens: 350 }) });
    const data = await response.json();
    if (!response.ok) { console.error('OpenAI error:', data); return res.status(502).json({ error: 'The AI service could not answer right now.' }); }
    const text = data.output_text || data.output?.flatMap(item => item.content || []).filter(item => item.type === 'output_text').map(item => item.text).join(' ') || 'Sorry, I could not generate a response.';
    res.json({ answer: text });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Something went wrong on the server.' }); }
});

app.use((req, res) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/')) return res.sendFile(path.join(__dirname, 'index.html'));
  res.status(404).json({ error: 'Not found.' });
});

app.listen(PORT, () => console.log(`Smart Parenting Assistant running on port ${PORT}`));
