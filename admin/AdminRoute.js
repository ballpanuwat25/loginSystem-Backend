import express from "express";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const salt = 10;
const app = express();

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '12345678',
    database: 'special_problem'
});

app.get("/admin-list", (req, res) => {
    db.query("SELECT * FROM admin", (err, result) => {
        if (err) {
            console.log(err);
        } else {
            res.send(result);
        }
    });
});

const verifyAdmin = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "Access denied" });
    } else {
        jwt.verify(token, "jwtSecret", (err, decoded) => {
            if (err) {
                return res.json({ Error: "Access denied" });
            } else {
                req.adminName = decoded.adminName;
                req.adminUsername = decoded.adminUsername;
                req.adminPassword = decoded.adminPassword;
                req.adminTel = decoded.adminTel;
                next();
            }
        });
    }
};

app.get("/admin", verifyAdmin, (req, res) => {
    res.json({
        adminName: req.adminName,
        adminUsername: req.adminUsername,
        adminPassword: req.adminPassword,
        adminTel: req.adminTel,
    });
});

app.post("/admin-login", (req, res) => {
    const sql = "SELECT * FROM admin WHERE Admin_Username = ?";
    db.query(sql, [req.body.Admin_Username], (err, result) => {
        if (err) return res.json({ Error: err });
        if (result.length > 0) {
            bcrypt.compare(req.body.Admin_Password, result[0].Admin_Password, (error, response) => {
                if (error) return res.json({ Error: error });
                if (response) {
                    const token = jwt.sign(
                        {
                            adminName: result[0].Admin_Name,
                            adminUsername: result[0].Admin_Username,
                            adminPassword: result[0].Admin_Password,
                            adminTel: result[0].Admin_Tel,
                        },
                        "jwtSecret",
                        { expiresIn: "1d" }
                    );
                    res.cookie("token", token, { httpOnly: true }).send();
                } else {
                    res.json({ Error: "Wrong username/password combination" });
                }
            });
        } else {
            res.json({ Error: "Wrong username/password combination" });
        }
    });
});

app.post("/admin-register", (req, res) => {
    const sql = "INSERT INTO admin (Admin_Name, Admin_Username, Admin_Password, Admin_Tel) VALUES (?, ?, ?, ?)";
    bcrypt.hash(req.body.Admin_Password, salt, (err, hash) => {
        if (err) return res.json({ Error: err });
        db.query(sql, [req.body.Admin_Name, req.body.Admin_Username, hash, req.body.Admin_Tel], (error, result) => {
            if (error) return res.json({ Error: error });
            res.send(result);
        });
    });
});

app.post("/admin-forget-password", (req, res) => {
    const sqlSelect = "SELECT * FROM admin WHERE Admin_Username = ?";
    const sqlUpdate = "UPDATE admin SET Admin_Password = ? WHERE Admin_Username = ?";

    db.query(sqlSelect, [req.body.Admin_Username], (err, result) => {
        if (err) {
            return res.json({ Error: err });
        }

        if (result.length > 0) {
            const username = result[0].Admin_Username;
            if (req.body.Admin_Password.length < 8) {
                return res.json({ Error: "Password must be at least 8 characters" });
            }

            bcrypt.hash(req.body.Admin_Password, salt, (error, hash) => {
                if (error) {
                    return res.json({ Error: error });
                }

                db.query(sqlUpdate, [hash, username], (error, result) => {
                    if (error) {
                        return res.json({ Error: error });
                    }

                    res.send(result);
                });
            });
        } else {
            res.json({ Error: "Username does not exist" });
        }
    });
});


app.get("/admin-logout", (req, res) => {
    res.clearCookie("token").send();
});

export default app;