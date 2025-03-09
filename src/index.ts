import express from "express";

import path from "path";


const app = express();

const port =  3000;


app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, "./views/index.html"))
});

app.get('/signup', (req, res) => {
  res.sendFile(path.resolve(__dirname, "./views/signup.html"))
});

console.log('app ran')


app.listen(port,() => {
    console.log(`Server is running at http://localhost:${port}`);
})




