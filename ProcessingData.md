#### Format

1. Allow @decorator which specifies the format (as a 'secret' field?)
2. Maybe the decorator will auto-register the request in a dictionary?

> Look up for object by code.

Server Python Parsing process:

1. Parse the header, it has a known structure.
2. Look up for the request code.
3. Fetch format and bytes by the request type, parse the request that we want.
4. Execute the logic. Logic builds a response data object.
5. The object's format is looked up by it's type. 
6. The object gets desiralized into bytes.



Client C++ Parsing process:

1. Do logic.
2. Build a struct with all the data.
3. Send it using the template method.
4. Wait for response of length ? by another template method.
5. Do logic.