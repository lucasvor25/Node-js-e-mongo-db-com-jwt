require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

const User = require('./Models/User')

app.use(express.json())

app.get('/', (req, res,) => {
res.status(200).json({msg:"Bem vindo"})
})

app.get('/user/:id',checkToken, async (req , res) => {
    const id = req.params.id

    const user = await User.findById(id, '-password')
    if(!user) {
        return res.status(404).json({msg: 'Usuario nao encont'})
    }
    res.status(200).json({user})

})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ') [1]

    if(!token) {
        return res.status(401).json({msg:"Nao tem token"})
    }
    try {

const secret = process.env.SECRET

jwt.verify(token, secret)
next()

    }catch(err) {
        res.status(400).json({msg: "token invalido"})
    }
}


app.post('/registro' , async(req, res) => {
    const {name, email, password, confirmpassword} = req.body
if(!name) {
    return res.status(422).json({msg: 'O nome é obrigatorio'})
} 
if(!email) {
    return res.status(422).json({msg: 'O email é obrigatorio'})
}
if(!password) {
    return res.status(422).json({msg: 'A senha é obrigatorio'})
}
if(!confirmpassword) {
    return res.status(422).json({msg: 'As senhas nao conferem'})
}

const userExists = await User.findOne({email:email})
if(userExists) {
    return res.status(422).json({msg: "use outro email"})
}
const salt = await bcrypt.genSalt(12)
const passwordHash = await bcrypt.hash(password, salt)

const user = new User({
    name,
    email,
    password: passwordHash,
})
try{
await user.save()
res.status(201).json({msg: "Usuario criado com sucesso"})
}catch(erro) {
    res.send(500).json({msg:"Erro no servidor"})
console.log(erro)
}

})

app.post('/user', async (req, res) => {
    const {email, password} = req.body

    if(!email) {
        return res.status(422).json({msg: 'O email é obrigatorio'})
    }
    if(!password) {
        return res.status(422).json({msg: 'A senha é obrigatorio'})
    }
    const user = await User.findOne({email:email})

    if(!user) {
        return res.status(422).json({msg: "Usuario nao encontrado"})
    }

    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword) {
        return res.status(422).json({msg: "Senha invalida"})
    }
    try {
    const secret = process.env.SECRET
    const token = jwt.sign({
        id: user._id
    },
    secret
    )
    res.status(200).json({msg: "Autenticacao enviada com sucesso", token})
        
    }catch (erro) {
        console.log(erro)
        res.status(500).json({msg:"Algum erro no server"})
    }
})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.mfexy.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`)
.then(() => {
    app.listen(3000)
    console.log('Conectou ao banco')
})
.catch((err) => console.log(err))

