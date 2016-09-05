HOW TO RUN
===========

To run the deployed version of this project,
visit http://basic-blog-1356.appspot.com/

To run this project on your local machine:
	- make sure you have the Google App Engine SDK
	  for Python installed and configured on your machine
	- navigate to the project directory in your terminal
	- type the command: 'dev_appserver.py .'
	- the project will run on localhost, port 8080
	  by default.  to see the page, visit
	  http://localhost:8080/

PROJECT INFO
=============

- only logged in users can create, comment on, and like blog entries
- only owners of blog entries can edit or delete them
- only owners of comments can edit or delete them
- users can like other peoples' blog entries, but not their own
- users can only like a blog entry once

- if a user tries to perform an unauthorized action, they will be
  redirected either to the home page or to the blog entry permalink page