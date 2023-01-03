# pem2jwk
This tool converts the keys and certificates in PEM format to JWK format. 

```
% ./pem2jwk
Usage of ./pem2jwk:
 <options> pemfile1 <pemfile2>
  -alg string
    	The JWA alg to be set (default "PS256")
  -kid string
    	The kid of the key
  -kidFromFile
    	Generate the kid from filename
  -use string
    	The usage of the key (default "sig")
  -x5atts
    	If the x5* attributes should be created
```

