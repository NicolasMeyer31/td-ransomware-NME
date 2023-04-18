# I. Chiffrement

## Question 1

L'algorithme de chiffrement utilisé est appelé XOR. 
Cet algorithme n'est pas robuste. Il peut être cassé par des attaques de force brute. De plus, la sécurité de l'algorithme dépend fortement de la clé utilisée et peut conduire à des vulnérabilités.

## Question 2

Hasher directement la clé et le sel n'est pas suffisant pour produire une clé suffisamment sécurisée. Il est possible d'effectuer une attaque par force brute pour deviner la clé d'origine en testant toutes les combinaisons possibles. Un simple hash ne prend pas en compte la longueur de la clé et peut être facilement cassé.

L'utilisation d'un HMAC nécessite la gestion de la clé secrète supplémentaire, ce qui peut compliquer la mise en œuvre.

## Question 3

Il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent pour éviter d'écraser un token existant. Si ce dernier est écrasé, cela pourrait entraîner des problèmes de sécurité et d’authentification. 
De plus, si le fichier token.bin existe déjà, cela signifie que les éléments cryptographiques ont déjà été générés et enregistrés localement, et qu'ils ont probablement déjà été envoyés au CNC. 

## Question 4

Afin de valider une clé 'valide', il est possible de dériver une clé à partir du sel et de la clé proposée. En comparant la clé dérivée ainsi obtenue avec le token stocké dans self._token, on peut vérifier si la clé  est correcte. Si les deux valeurs correspondent, cela indique que la clé est valide et peut être utilisée pour décrypter les données.