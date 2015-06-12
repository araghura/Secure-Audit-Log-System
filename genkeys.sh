#/!/bin/bash
pvtoutfileT="priv.key.t.pem"
puboutfileT="pub.key.t.pem"
pvtoutfileU="priv.key.u.pem"
puboutfileU="pub.key.u.pem"
pvtoutfileC="priv.key.c.pem"
puboutfileC="pub.key.c.pem"
algo="rsa"
numrsa=1024


#openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:1024 -out priv.key
#Generate all the public and private keys using rsa
openssl genpkey -outform PEM -algorithm $algo -pkeyopt rsa_keygen_bits:$numrsa -out $pvtoutfileT
openssl genpkey -outform PEM -algorithm $algo -pkeyopt rsa_keygen_bits:$numrsa -out $pvtoutfileU
openssl genpkey -outform PEM -algorithm $algo -pkeyopt rsa_keygen_bits:$numrsa -out $pvtoutfileC

chmod u+x $pvtoutfileT
chmod u+x $pvtoutfileU
chmod u+x $pvtoutfileC

openssl pkey -in $pvtoutfileT -pubout -outform PEM -out $puboutfileT
openssl pkey -in $pvtoutfileU -pubout -outform PEM -out $puboutfileU
openssl pkey -in $pvtoutfileC -pubout -outform PEM -out $puboutfileC

chmod u+x $puboutfileT
chmod u+x $puboutfileU
chmod u+x $puboutfileC

openssl req -new -batch -x509 -key $pvtoutfileT -out cert.u.pem -days 1095
#openssl ca -selfsign -batch -keyfile $pvtoutfileU -out cacert.pem -days 1095



#echo "Finished first command"
#openssl req -batch -new -key $pvtoutfileU -out /homes/araghura/security_systems/cert.csr 
#echo "Finished Second Command"
#openssl ca -verbose -keyfile $pvtoutfileT -cert /homes/araghura/security_systems/demoCA/newcerts/cacert.pem -batch -in cert.csr -out certu.csr -days 1024
#echo "Finished third command"





#openssl x509 -in cacert.pem -text

