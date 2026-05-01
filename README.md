# insecure-webapi

This repo is a sample of worst WebAPI in security terms
I made this for my students. It's about all not to do in WebDev
**Please Never use this in production.**

For Installing check Instalar.md

NEW example:

Registration:
fetch("https://insecure-webapi.onrender.com/Registro", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    uname: "Arsheo",
    email: "mailgenerico@gmail.com",
    password: "LaContraseñaEsContraseña"
  })
})
.then(r => r.text())
.then(console.log)

Login:
let miToken = "";

fetch("https://insecure-webapi.onrender.com/Login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    uname: "testsuario",
    password: "123456MasGenericaNoSePuede"
  })
})
.then(r => r.json())
.then(data => {
  miToken = data.D;
  console.log("Token:", miToken);
})

Upload image:
fetch("https://insecure-webapi.onrender.com/Imagen", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    token: "PEGA_TU_TOKEN_AQUI (Lo genera la funcion anterior)",
    name: "imagen_pruebaX",
    ext: "png",
    data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
  })
})
.then(r => r.text())
.then(console.log)
