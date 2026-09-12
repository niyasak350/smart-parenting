require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname)));

const SYSTEM_PROMPT = `You are Smart Parenting Assistant, a friendly general parenting guidance assistant. Give short, practical, easy-to-understand advice for parents and caregivers. You may discuss routines, nutrition basics, sleep habits, activities, emotions, child development, and mother wellness in general terms. Do not diagnose medical conditions, prescribe medicines, give medication doses, or replace a pediatrician or other qualified clinician. If a message suggests an emergency, serious symptoms, self-harm, danger to a child, severe postpartum mental-health symptoms, or another urgent situation, clearly advise contacting local emergency services or an appropriate healthcare professional immediately. Never claim certainty about a medical condition. Respect privacy and do not ask for unnecessary sensitive information.`;

app.post('/api/chat', async (req, res) => {
  try {
    const { message, childAge } = req.body || {};
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Please enter a question.' });
    }

    if (!process.env.OPENAI_API_KEY) {
      return res.status(503).json({ error: 'AI service is not configured yet. Add OPENAI_API_KEY on the server.' });
    }

    const context = childAge ? `The child age provided by the parent is ${childAge}. Use this only when it is relevant.` : '';
    const response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-5-mini',
        instructions: SYSTEM_PROMPT,
        input: `${context}\nParent question: ${message.trim()}`,
        max_output_tokens: 350
      })
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('OpenAI error:', data);
      return res.status(502).json({ error: 'The AI service could not answer right now.' });
    }

    const text = data.output_text || data.output?.flatMap(item => item.content || [])
      ?.filter(item => item.type === 'output_text')
      ?.map(item => item.text)
      ?.join(' ') || 'Sorry, I could not generate a response.';

    res.json({ answer: text });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Smart Parenting Assistant running on port ${PORT}`);
});
