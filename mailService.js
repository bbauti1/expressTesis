const nodemailer = require('nodemailer');

const sendVerificationEmail = (email, token) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'comunicadosdigitalizados@gmail.com',
            pass: 'tsee tqnl pemm htgg'
        }
    });

    const mailOptions = {
        from: 'comunicadosdigitalizados@gmail.com',
        to: email,
        subject: 'Verifica tu cuenta',
        html: `<p>Buenas! Se necesita que verifique tu cuenta haciendo clic en el siguiente enlace:</p>
               <a href="http://localhost:3000/verify-email?token=${token}">Verificar cuenta</a>`
    };    

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error enviando email:', error);
        } else {
            console.log('Email enviado: ' + info.response);
        }
    });
};

module.exports = sendVerificationEmail;
