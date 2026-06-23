Задания: TRAFFIC ANALYSIS EXERCISE: EASY AS 123
Источник: Malware-Traffic-Analysis

Условие задачи:
Будучи динамичным и инициативным сотрудником Центра обеспечения безопасности (SOC), вы проверяете систему управления информацией и событиями безопасности (SIEM) и обнаруживаете несколько срабатываний сигнатур, указывающих на NetSupport Manager RAT с IP-адреса 45.131.214[.]85 через порт TCP 443. Активность началась 28 февраля 2026 года в 19:55 UTC.

Используя эту информацию, вы быстро извлекаете дамп сетевого трафика (pcap) с внутреннего IP-адреса, который вызвал эти оповещения. Теперь всё зависит от вас! Ожидается, что вы подготовите отчёт об инциденте, чтобы кто-то мог отследить заражённый компьютер и положить конец этой проблеме!

Характеристики вашей среды:

    Диапазон сегмента LAN: 10.2.28[.]0/24 (от 10.2.28[.]0 до 10.2.28[.]255)
    Домен: easyas123[.]tech
    Название среды Active Directory (AD): EASYAS123
    Контроллер домена Active Directory (AD): 10.2.28[.]2 — EASYAS123-DC
    Шлюз сегмента LAN: 10.2.28[.]1
    Широковещательный адрес сегмента LAN: 10.2.28[.]255


ВАША ЗАДАЧА:
В рамках этого упражнения ответьте на следующие вопросы для вашего отчёта об инциденте:

    Каков IP-адрес заражённого Windows-клиента?
    Каков MAC-адрес заражённого Windows-клиента?
    Каково имя хоста (hostname) заражённого Windows-клиента?
    Каково имя учётной записи пользователя с заражённого Windows-клиента?
    Каково полное имя пользователя, связанное с этой учётной записью?

Решение:

1. Поиск IP-адреса заражённого клиента
Я начал с того, что решил отсеять шумовой трафик (SSDP, широковещательные запросы) и сосредоточиться на активности, которая могла бы указать на клиентские запросы к C2. Для этого я применил фильтр:

(http.request or tls.handshake.type eq 1) and !(ssdp)

Этот фильтр показал мне все HTTP-запросы и TLS-рукопожатия, исключая SSDP. Просматривая результаты, я заметил, что все подозрительные соединения на 45.131.214.85:443 исходят с одного внутреннего адреса:

IP-адрес заражённого клиента: 10.2.28.88

2. Определение MAC-адреса
Зная IP-адрес, я кликнул по любому пакету с этим IP и в деталях канального уровня (Ethernet) нашёл MAC-адрес отправителя:

MAC-адрес заражённого клиента: 00:19:d1:b2:4d:ad


3. Получение hostname (имени компьютера)
Чтобы узнать имя хоста в домене Windows, я использовал фильтр для NetBIOS Name Service:

nbns

В ответах NBNS я нашёл запись, где указано имя компьютера:

Hostname заражённого клиента: DESKTOP-TEYQ2R


4. Имя учётной записи пользователя
В трафике присутствовала аутентификация Kerberos (порт 88). Я отфильтровал пакеты Kerberos, относящиеся к моему заражённому IP:

kerberos && ip.addr eq 10.2.28.88

В одном из билетов (TGT) я нашёл поле CNameString, которое содержало имя пользователя:

Имя учётной записи: brolf

5. Полное имя пользователя
Чтобы установить полное имя (displayName), я воспользовался поиском по пакетам (Edit → Find Packet). В строке поиска я ввёл Rolf (часть имени, полученного ранее), выбрал поиск строки с учётом регистра и отметил опцию "Multiple occurrences" (множественные вхождения).
Wireshark нашёл несколько вхождений в контексте протоколов SMB, LDAP или Kerberos. В одном из них было указано полное имя пользователя:
Полное имя пользователя: Becka Rolf

Результаты расследования:
IP-адрес заражённого клиента	10.2.28.88
MAC-адрес			00:19:d1:b2:4d:ad
Hostname			DESKTOP-TEYQ2R
Имя учётной записи		brolf
Полное имя пользователя		Becka Rolf


Заключение
В ходе выполнения задания я успешно идентифицировал заражённую машину и её пользователя, используя только pcap-файл и возможности Wireshark. Этот опыт показал мне, как важно уметь фильтровать трафик и находить скрытые детали (например, имена в Kerberos-билетах). Я планирую продолжать практиковаться на аналогичных дампах, чтобы улучшить навыки реагирования на инциденты.

English version
Tasks: TRAFFIC ANALYSIS EXERCISE: EASY AS 123
Source: Malware-Traffic-Analysis

Task Description:
As a dynamic and proactive member of the Security Operations Center (SOC), you're monitoring the Security Information and Event Management (SIEM) system and discover several signature triggers pointing to a NetSupport Manager RAT running from IP address 45.131.214[.]85 on TCP port 443. This activity began on February 28, 2026, at 19:55 UTC.

Using this information, you quickly extract a network traffic dump (pcap) from the internal IP address that triggered these alerts. Now it's up to you! You're expected to prepare an incident report so someone can trace the infected computer and put an end to this problem!

Your environment characteristics:
LAN segment range: 10.2.28[.]0/24 (from 10.2.28[.]0 to 10.2.28[.]255)
Domain: easyas123[.]tech
Active Directory (AD) environment name: EASYAS123
Active Directory (AD) domain controller: 10.2.28[.]2 - EASYAS123-DC
LAN segment gateway: 10.2.28[.]1
LAN segment broadcast address: 10.2.28[.]255

YOUR TASK:
As part of this exercise, answer the following questions for your incident report:

What is the IP address of the infected Windows client?
What is the MAC address of the infected Windows client?
What is the hostname of the infected Windows client?
What is the user account name of the infected Windows client?
What is the full username associated with this account?

Solution:

1. Find the IP address of the infected client
I started by filtering out noise traffic (SSDP, broadcast requests) and focusing on activity that could indicate client requests to C2. To do this, I applied the filter:

(http.request or tls.handshake.type eq 1) and !(ssdp)

This filter showed me all HTTP requests and TLS handshakes, excluding SSDP. While reviewing the results, I noticed that all suspicious connections to 45.131.214.85:443 originated from a single internal address:

IP ​​address of the infected client: 10.2.28.88

2. Determining the MAC address
Knowing the IP address, I clicked on any packet with that IP address and found the sender's MAC address in the data link layer (Ethernet) details:

MAC address of the infected client: 00:19:d1:b2:4d:ad

3. Obtaining the hostname (computer name)
To find the hostname in the Windows domain, I used a filter for the NetBIOS Name Service:

nbns

In the NBNS responses, I found an entry indicating the computer name:

Hostname of the infected client: DESKTOP-TEYQ2R

4. User account name
The traffic contained Kerberos authentication (port 88). I filtered out Kerberos packets related to my infected IP:

kerberos && ip.addr eq 10.2.28.88

In one of the tickets (TGT), I found a CNameString field that contained the username:

Account Name: brolf

5. Full Username
To find the full name (displayName), I used a packet search (Edit → Find Packet). In the search bar, I entered Rolf (part of the name obtained earlier), selected case-sensitive search, and checked the "Multiple occurrences" option.
Wireshark found multiple occurrences in the context of the SMB, LDAP, or Kerberos protocols. One of them listed the user's full name:
Full username: Becka Rolf

Investigation results:
IP address of infected client: 10.2.28.88
MAC address: 00:19:d1:b2:4d:ad
Hostname: DESKTOP-TEYQ2R
Account name: brolf
Full username: Becka Rolf

Conclusion
During the task, I successfully identified the infected machine and its user using only a pcap file and Wireshark. This experience taught me the importance of filtering traffic and finding hidden details (such as names in Kerberos tickets). I plan to continue practicing on similar dumps to improve my incident response skills.