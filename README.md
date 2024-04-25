# WAPH-Web Application Programming and Hacking

## Instructor: Dr. Phu Phung

# Project Topic/Title: A MINI FACEBOOK APPLICATION

# Team members

1. kalyan Kamati, kamatikn@mail.uc.edu
2. Surya Sarath Bharadwaj Pulla, pullasj@mail.uc.edu
3. Sri Ram Sai Vamsi Kuchimanchi , kuchimsi@mail.uc.edu
4. Suryateja Chennapragada, chennasj@mail.uc.edu

# Project Management Information

Source code repository (private access): (https://github.com/waph-team22/waph-teamproject.git)

Project homepage (public): (https://github.com/waph-team22/waph-team22.github.io.git)


# Implementation and demos:

- Registration of an account from any user: 

![Figure 1:](images/final1.png)

- Logging-in:

- login:
  ![Figure 2:](images/final2.png)

- Changing the password:
  ![Figure 3:](images/final3.png)

-Adding a new post:
 ![Figure 3:](images/final4.png)
 ![Figure 4:](images/final4-1.png)
 
- Editing posts:
   ![Figure 5:](images/final5.png)
  ![Figure 6:](images/final5-1.png)

- Deleting a post:
 ![Figure 7:](images/final6.png)

-Adding comments on any post:
  ![Figure 8:](images/final7.png)
  ![Figure 9:](images/final7-1.png)

-Real-time chat with other users:
![Figure 10:](images/final8.png)
![Figure 11:](images/final8-1.png)

- Superusers can:
- Login (with the account added directly in the database):
  ![Figure 12](images/final9.png)
  ![Figure 13:](images/superuser.png)
  ![FIgure 14:](images/final9-1.png)

-Viewing the list of registered users.:
![Figure 15:](images/final9-1.png)

-Disable (not delete) a registered user:
![Figure 16:](images/final10.png)
![Figure 17:](images/final10-1.png)
![Figure 18:](images/final10-2.png)

-Enable a registered user:

![Figure 19:](images/final11.png)
![Figure 20:](images/final11-1.png)
![Figure 21:](images/final11-2.png)

# Security and Non-Functional Requirements: 

- deployment on HTTPS:

  ![Figure 22:](images/sf1.png)


-Hashing of passwordsin the database and no MySQL root account used for the PHP code:

![Figure 23:](images/sf2.png)

- All SQL must be in Prepared Statements:

-Prepared statements are used to segregate user-entered data from the SQL query itself. This is critical for preventing SQL injection attacks, which occur when incorrect SQL code is injected to application queries, granting the attacker access to see or modify database information.

- ```sql
  
  $prepared_sql = "INSERT INTO posts (content, author) VALUES (?, ?)"; 
  $stmt = $mysqli->prepare($prepared_sql);
  $stmt->bind_param('ss', $content, $author);
  ```
- HTML outputs must be sanitized:

  ``` sql
  if (isset($_POST["username"]) and isset($_POST["password"])) {

      if (checklogin_mysql($_POST["username"],$_POST["password"])) {

        $_SESSION['authenticated'] = TRUE;
        $_SESSION['username']= $_POST["username"];
    //$sanitized_username = htmlspecialchars($_POST['username'])
      }else{
        session_destroy();
        echo "<script>alert('Invalid username/password');window.location='form.php';</script>";
        die();
  }
  }
  if (!isset($_SESSION['authenticated']) or $_SESSION['authenticated']!= TRUE){
   session_destroy();
   echo "<script>alert('you have not login.please login')</script>";
   header("Refresh: 0; url=form.php");
   die();
  }
  if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    echo "<script>alert('Not authorized. Please login first.'); window.location='form.php';</script>";
    exit;
  }
   ```

- Access control for registered users and super users:

Management of sessions:

Calling session_start() at the start of the code initiates a PHP session.
This allows the programme to save and retrieve user data across multiple pages.



Method of authentication:

The code determines whether the form submission request method, POST, is used.
It retrieves the password and username submitted through the POST data.
The provided credentials are compared to hardcoded superuser credentials.

Assigning roles:

The code saves the username and sets session variables to indicate successful authentication if the provided credentials match those of the super user:

'authenticated' in $_SESSION['] = true;
$username = $_SESSION['username'];




Control of access:

When the login process is complete, the code redirects the user to dashboard.php.
To restrict access to just authorized super users, the dashboard page can check the session variables ($_SESSION['authenticated'] and $_SESSION['username']).


Error management

If the credentials entered are incorrect, an error message is stored in the $loginError variable and shown on the login page.


Results:

The code generates an HTML form for the super user login.
Whenever there is an error message, it appears within the form.
The form transfers the credentials received (super_user.php) to the same file for verification.
Password hashing: To mitigate security threats, passwords should be salted and hashed before being stored in a database.
Validating user inputs (password and username) is critical to preventing security issues such as SQL injection and cross-site scripting attacks.
Session management should include additional security methods such as regenerating session IDs after authentication while setting the appropriate session cookie flags (e.g., HttpOnly, Secure).
Database integration: To improve scalability and maintainability, super user credentials should be fetched from a database rather than hardcoded.


- A regular user cannot log in as a superuser:

  A common user cannot log in as a superuser since their credentials do not match the database of the super user login, where they cannot modify, post, or even log in...
  ![Figure 24](images/final10-1.png)

- Session Authentication and Hijacking Prevention

 The code initiates a PHP session by calling session_start().
  The $_SESSION['authenticated'] variable is verified to ensure that it is set to true.
  If the user is not authenticated, the code utilises header("Refresh: 0; url=form.php") to redirect them to the form.php login page.
  After successful authentication, the code assigns the proper values to the $_SESSION['authenticated'] and $_SESSION['username'] variables.

-  CSRF ProtectionFor crucial operations, CSRF (Cross-Site Request Forgery) protection is typically implemented by creating and validating a token.

A unique CSRF token is generated at the start of the PHP script and stored in the user's session:
```php
<?php
session_start();

// Generate a CSRF token if it doesn't exist
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
```
incorporating the CSRF token into a hidden input box on forms that perform sensitive operations (like changing passwords or updating user data).
```html
<form action="update_password.php" method="post">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <!-- Form fields -->
    <input type="submit" value="Update Password">
</form>
```
On the server end, the CSRF token was validated: The CSRF token that was received was checked against the session's storage by the PHP script that controls form submission.

- Incorporating a front-end CSS template that is available for free
HTML Structure: The HTML structure is a simple layout with placeholders for user data that is dynamic content and action buttons.
CSS Styles: These styles define the appearance of elements such as bodies, headers, paragraphs, buttons, and containers. For smaller displays, responsive styles (@media query) are also included.
PHP Application:
manages user sessions and authentication (session_start()).
confirms if the user has successfully authenticated and is logged in.
retrieves user information from the database using the getUserProfile function.
includes the checklogin_mysql function, which uses a MySQL database to validate user credentials.
stops the hijacking of sessions,
Database integration: The PHP code interacts with the waph_team22 MySQL database to retrieve user data and validate credentials.
In order to prevent SQL injection, it uses prepared statements ($stmt->bind_param).

The code contains the information about the database connection (localhost, team22, Pa$$w0rd,waph_team22).

-A team project website
[A team project website](https://waph-team22.github.io/)
(https://waph-team22.minifacebook.com)


- Video Demonstration:

  



# Appendix
Source code repository (private access): (https://github.com/waph-team22/waph-teamproject.git)

Project homepage (public): (https://github.com/waph-team22/waph-team22.github.io.git)

Team website- 
(https://waph-team22.minifacebook.com)
