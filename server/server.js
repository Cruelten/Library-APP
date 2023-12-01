const express = require('express')
const redis = require('redis')

const app = express();
const PORT = process.env.PORT || 4000;

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost';
const client = redis.createClient({url: REDIS_URL});

(async () => {
    client.connect()
  })();

app.get('/counter/:bookID', async (req, res) => {
  const {bookID} = req.params;
  try {
  const cnt = (await client.get(bookID)) || 0
  res.json({cnt})
  } catch(e) {
  res.json({errcode: 500, ermsg: 'redis err!'});
  }
  });

app.post('/counter/:bookID/incr', async (req, res) => {
  const { bookID } = req.params;
  try {
      let cnt = await client.get(bookID);
      if (cnt === null) {
          cnt = 0;
      }
      cnt = parseInt(cnt) + 1;
      await client.set(bookID, cnt);
      res.status(200).json({ cnt });
  } catch (e) {
     res.status(500).json({ errcode: 500, ermsg: 'Server error' });
  }
})


app.listen(PORT, () => {
    console.log(`Слушаю порт ${PORT}`)
  })