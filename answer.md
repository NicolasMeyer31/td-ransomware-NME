# I. Chiffrement

## Question 1

L'algorithme de chiffrement utilisé est appelé XOR. 
Cet algorithme n'est pas robuste. Il peut être cassé par des attaques de force brute. De plus, la sécurité de l'algorithme dépend fortement de la clé utilisée et peut conduire à des vulnérabilités.

## Question 2

Hasher directement la clé et le sel n'est pas suffisant pour produire une clé suffisamment sécurisée. Il est possible d'effectuer une attaque par force brute pour deviner la clé d'origine en testant toutes les combinaisons possibles. Un simple hash ne prend pas en compte la longueur de la clé et peut être facilement cassé.

L'utilisation d'un HMAC nécessite la gestion de la clé secrète supplémentaire, ce qui peut compliquer la mise en œuvre.
