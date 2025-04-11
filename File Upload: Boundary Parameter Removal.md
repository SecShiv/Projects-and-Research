### Weird File Upload Vector: MultiPart Boundary Parameter Removal (with PoC)

So during my 2nd Semester, 1st year in Uni, I and other students were given a practical CTF assignment. During this, i spent 1-2 weeks testing for different stuff, even after I got the flags.
One of the issues, which was taught in the lectures was a file upload attack using magic bytes to get shell.

However, I did find another unintended bypass by completely removing the boundary parameter at the bottom, more specifically the ```Content-Disposition: form-data; name="submit"```.
Removing other boundary parameters weren't successful, only this one for some reason.

What is ```Content-Type: multipart/form-data``` tho? - It's just simple HTML form but for handling large file uploads. The boundary is used to seperate parameters.
Like ```name="submit"``` is just a parameter with a boundary thing on top of it. 

My initial theory was that maybe the server was accepting it as long as it was a POST request, included the ```content-type: multipart/form-data``` and the body as PHP shell code.
Meaning, just sending a POST request with the payload as the body, no upload whatsoever, but ofc it failed. 

I was deep researching for hours as to what the issue could be, until I came across these goldmines, so the PHP server-side code is not validating the multipart parser properly.
**(Idk PHP Programming/Code but I'm learning as much as I can reading the docs, functions and using ChatGPT.)**

- https://blog.sicuranext.com/breaking-down-multipart-parsers-validation-bypass/#bypass-4-missing-closing-boundary-string
- https://bugs.php.net/bug.php?id=81987
- https://stackoverflow.com/questions/5483851/manually-parse-raw-multipart-form-data-data-with-php

Since I already had shell now, I decided to take a look at the file upload PHP code in webroot, and sort of come up with my conclusion of what's happening.

The PHP Code:

```<?php
$target_dir = "submissions/";
$target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
$uploadOk = 1;
$imageFileType = strtolower(pathinfo($target_file,PATHINFO_EXTENSION));
$msg = "No Form Submission";
$msg_type = "alert-danger";

// Check if image file is a actual image or fake image
if(isset($_POST["submit"])) {
  $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
  if($check !== false) {
    $msg =  "<p>File is an image - " . $check["mime"] . ".</p>";
    $msg_type = "alert-success";
    $uploadOk = 1;
  } else {


    $msg = "<p>File is not an image.</p>";
    $msg_type = "alert-warning";
    $uploadOk = 0;
  }
}

// Check if file already exists
if (file_exists($target_file)) {
  $msg =  "Sorry, file already exists.";
  $msg_type = "alert-warning";
  $uploadOk = 0;
}

// Check file size
if ($_FILES["fileToUpload"]["size"] > 500000) {
    $msg = "Sorry, your file is too large.";
    $msg_type = "alert-warning";
  $uploadOk = 0;
}

// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
  $msg = $msg. "<p>Sorry, your file was not uploaded.</p>";
// if everything is ok, try to upload file
} else {
  if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
    $msg = "<p>The file ". htmlspecialchars( basename( $_FILES["fileToUpload"]["name"])). " has been uploaded.</p>";
    $msg_type = "alert-success";
  } else {
    $msg =  "Sorry, there was an error uploading your file.";
    $msg_type = "alert-danger";
  }
}
?>
```

Take a closer look over here:
```
// Check if image file is a actual image or fake image
if(isset($_POST["submit"])) {
  $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
  if($check !== false) {
    $msg =  "<p>File is an image - " . $check["mime"] . ".</p>";
    $msg_type = "alert-success";
    $uploadOk = 1;
  } else {
```

We see that in the backend, that after a POST "submit" request is sent, how the PHP code is handling this, doing the usual file checks.
So ```"if"```, ```"POST"```, ```"submit"``` > Do these checks. 

This is a conditional value, so what if the attacker doesn't add the "submit" parameter in the HTTP request?

My conclusion:
The code will be sent to the server, but it will skip the first check since the "submit" parameter is not in the POST request, but still execute other parts of the PHP code
such as ```"if file exists"``` (tested), so that basically bypasses all of its file upload checks in place.

This is just bad backend coding practices, the security checks are relied directly on the "submit" POST parameter that's sent by the user/attacker.
Rather, they should do validation which can't be manipulated.

### PoC
https://github.com/user-attachments/assets/d023f1ea-cd55-4fa6-9a65-2c542d00ddcc


