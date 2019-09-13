TUN and Routing
===============

### Задача

Создать TUN интерфейс и пустить через него весь сетевой трафик в системе. Допустим, наш интерфейс называется tun0. Мы хотим

- либо
  1. **Перенаправить** все пакеты, вышедшие не из tun0 в tun0,
  2. Передавать из tun0 те же пакеты, что и получать,
  3. Выходящее пакеты передавать на интерфейсы/адреса для которых они изначально предназначались,

- либо
  1. **Отзеркалить** весь трафик, вышелший не из tun0 в tun0.

Вариант зеркалирования пришёл мне в голову, когда я писал этот текст, и пока подробно не изучался.

### Инструменты

Есть таблицы маршрутизации, есть iptables. Это разные штуки для разных целей. Но кажется некоторые задачи можно решать либо тем, либо другим, а в некоторых случаях их полезно использовать в связке: iptables может маркировать пакеты, а дальше эти маркеры могут использоваться как фильтры в таблицах маршрутизации.

### Подробнее про routing

В базовом варианте ядро решает, куда отправлять пакеты, основываясь только на адресе назначения. Структура, описывающая направления, называется **routing table**. Посмотреть на неё можно командой `ip route show` или просто `route`. Это выведет содержимое таблицы main. Существуют и другие:

```sh
cat /etc/iproute2/rt_tables # tables 
ip route show table local  # records from table 'local'
ip route show table unspec # records from all tables
```

Для поддержки более сложных сценариев маршрутизации используется **policy routing**. Про него неплохо написано в `man ip rule`. Так вот он позволяет по набору фильтров (входящий/исходящий интерфейс, src/dest ip, fwmark, etc.) выбрать routing table, согласно которой будет дальше маршрутизироваться этот пакет. **Посмотреть список правил** можно командой `ip rule`.

### Как сломать интернет на своей машине

```sh
# terminal 1, root user
./main
# assume output
# tun0

# terminal 2, root user
ip link set tun0 up
ip addr add 10.0.0.1/24 dev tun0 # *

# add new routing table
echo 100 test >> /etc/iproute2/rt_tables

# route everything to some address from subnet we assigned to tun0
# see *
ip route add default via 10.0.0.2 dev tun0 table test

# route all packets with table 'test'
ip rule add from all lookup test priority 10000

curl "https://ya.ru"
# and look at terminal 1
```