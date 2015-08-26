# Backend du site inscription.resel.fr

### Installation de Django
D'abord il faut installer le packet-manager [Pip](https://pypi.python.org/pypi/pip)

Deux versions de Django existent, donc deux façons pour l'installer :
* python2.7
```
    pip install django
```
* python3
```
    pip3 install django
```

### Modules requis
Puisqu'on utilise le LDAP ResEl et le CAS de Télécom Bretagne, on a besoin de deux modules supplémentaires : [Django-CAS-ng](https://github.com/mingchen/django-cas-ng) et [Python-LDAP](http://www.python-ldap.org/).

L'installation de Python-LDAP se fait via pip, et cette de Django-CAS-ng par ... pip aussi !
```
    pip install python-ldap
    pip install django-cas-ng
```
Suivant votre machine, il se peut que d'autres modules soient nécessaires...

### Lancement de Django
Durant la phase de tests/mise en forme, le mieux est d'utiliser le daemon directement intégré à Django :
```
    python manage.py runserver
```

Pour la mise en production, il est recommandé de passer par un soft autre que Django. Dans notre cas, on a opté pour Gunicorn.
Pour cette solution, ce [tuto](http://tutos.readthedocs.org/en/latest/source/ndg.html) est particulièrement bien foutu.


