<?php
require_once("config.php");
   $error = null;
    if (isset($_POST['Envoyer']) ) {
            $user = $_POST['username'];
            $pass = $_POST['password'];
            $mail=$_POST['mail'];
            $role= $_POST['role'];
            $createtime = date('Y-m-d H:i:s');
            $sql = "SELECT * FROM users Where username='$user' OR email='$mail'";
            $result = mysqli_query($conn,$sql);

            if(mysqli_num_rows($result)> 0) {
                $error = "Cet utilisateur existe déjà";
            }else{
                $insertion=" INSERT INTO users(username,password,email,role,created_at )
                             VALUES('$user','$pass','$mail','$role','$createtime')
                 ";
                mysqli_query($conn,$insertion);
                header("location:login.php");
            }
    }

?>



<!DOCTYPE html>
<html lang="en">
        <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                 <link rel="stylesheet" href="style_login.css">
                <title>Inscription - Application Vulnérable</title>
        </head>
        <body>
            <div class="container">   
                        <div class="header">
                            <h1> <span class="vulnerability-badge">Inscription</span></h1>
                        </div>

                        <div class="form-container">
                            <?= (isset($error)) ? '<div class="error"><strong>'.$error.'</strong> </div>' :'' ?>
                            <form action="" method="post">
                                    <div class="form-group">
                                        <label for="username">Nom d'utilisateur</label>
                                        <input type="text" name="username" required placeholder="Votre nom d'utilisateur" id="username" >
                                    </div>

                                    <div class="form-group">
                                        <label for="password">Mot de passe</label>
                                        <input type="password" name="password" required placeholder="Votre mots de passe" id="password">
                                    </div>
                                    <div  class="form-group">
                                        <label for="email">Adresse mail</label>
                                        <input type="email" name="mail" required placeholder="Votre mail" id="email" >
                                    </div>
                                    <div class="form-group" >
                                        <select name="role">
                                            <option value="admin">Admin</option>
                                            <option value="user">user</option>
                                        </select>
                                    </div>
                                    <input type="submit" name="Envoyer"class="submit-btn"  value="Envoyer" >  
                            </form>
                            <div class="footer">
                                <p> Vous avez deja un compte ? <a href="login.php">Connectez-vous</Connectez-vous></a></p>
                            </div>
                        </div>
                        

            </div> 
        </body>
</html>