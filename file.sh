#!/bin/bash


GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' 


TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="report-${TIMESTAMP}.txt"

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}


print_header "Информация о системе"
 echo "================================"
 echo "Скрипт Айхана Сарала для безопасности vps-сервера"
 echo "> https://github.com/ayhan-dev/vps-m2g <"
 echo "Никакой безопасности нет, не полагайтесь только на этот скрипт."
 echo "Интернет-фараоны всегда скрываются"
 echo "================================"


OS_INFO=$(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
KERNEL_VERSION=$(uname -r)
HOSTNAME=$(hostname)
UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs)
CPU_CORES=$(nproc)
TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
PUBLIC_IP=$(curl -s https://api.ipify.org)
LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

print_info "Имя хоста" "$HOSTNAME"
print_info "Операционная система" "$OS_INFO"
print_info "Версия ядра" "$KERNEL_VERSION"
print_info "Время работы" "$UPTIME (с $UPTIME_SINCE)"
print_info "Модель процессора" "$CPU_INFO"
print_info "Количество ядер CPU" "$CPU_CORES"
print_info "Общий объём памяти" "$TOTAL_MEM"
print_info "Общий объём диска" "$TOTAL_DISK"
print_info "Публичный IP" "$PUBLIC_IP"
print_info "Средняя нагрузка" "$LOAD_AVERAGE"


echo "" >> "$REPORT_FILE"
print_header "Результаты аудита безопасности"

check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    
    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[PASS] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[WARN] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[FAIL] $test_name - $message" >> "$REPORT_FILE"
            ;;
    esac
    echo "" >> "$REPORT_FILE"
}

UPTIME=$(uptime -p)
UPTIME_SINCE=$(uptime -s)
echo -e "\nИнформация о времени работы системы:" >> "$REPORT_FILE"
echo "Текущее время работы: $UPTIME" >> "$REPORT_FILE"
echo "Система работает с: $UPTIME_SINCE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo -e "Время работы системы: $UPTIME (с $UPTIME_SINCE)"

if [ -f /var/run/reboot-required ]; then
    check_security "System Restart" "WARN" "Необходим перезапуск системы для применения обновлений"
else
    check_security "System Restart" "PASS" "Перезапуск не требуется"
fi

SSH_CONFIG_OVERRIDES=$(grep "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_ROOT=$(grep "^PermitRootLogin" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_ROOT=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_ROOT" ]; then
    SSH_ROOT="prohibit-password"
fi
if [ "$SSH_ROOT" = "no" ]; then
    check_security "SSH Root Login" "PASS" "Вход под root корректно отключен в конфигурации SSH"
else
    check_security "SSH Root Login" "FAIL" "Вход под root разрешен - это представляет собой угрозу безопасности. Отключите его в /etc/ssh/sshd_config"
fi

if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_PASSWORD=$(grep "^PasswordAuthentication" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_PASSWORD=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_PASSWORD" ]; then
    SSH_PASSWORD="yes"
fi
if [ "$SSH_PASSWORD" = "no" ]; then
    check_security "SSH Password Auth" "PASS" "Аутентификация по паролю отключена, используется только аутентификация по ключу"
else
    check_security "SSH Password Auth" "FAIL" "Аутентификация по паролю включена - рекомендуется использовать только аутентификацию по ключу"
fi



UNPRIVILEGED_PORT_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start)
SSH_PORT=""
if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
    SSH_PORT=$(grep "^Port" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
else
    SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
fi
if [ -z "$SSH_PORT" ]; then
    SSH_PORT="22"
fi
if [ "$SSH_PORT" = "22" ]; then
    check_security "SSH Port" "WARN" "Используется стандартный порт 22 - рекомендуется изменить на нестандартный порт для повышения безопасности"
elif [ "$SSH_PORT" -ge "$UNPRIVILEGED_PORT_START" ]; then
    check_security "SSH Port" "FAIL" "Используется непривилегированный порт $SSH_PORT - используйте порт ниже $UNPRIVILEGED_PORT_START для повышения безопасности"
else
    check_security "SSH Port" "PASS" "Используется нестандартный порт $SSH_PORT, что помогает предотвратить автоматические атаки"
fi


check_firewall_status() {
    if command -v ufw >/dev/null 2>&1; then
        if ufw status | grep -q "active"; then
            check_security "Firewall Status (UFW)" "PASS" "Брандмауэр UFW активен и защищает вашу систему"
        else
            check_security "Firewall Status (UFW)" "FAIL" "Брандмауэр UFW не активен - ваша система подвержена сетевым атакам"
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            check_security "Firewall Status (firewalld)" "PASS" "Firewalld активен и защищает вашу систему"
        else
            check_security "Firewall Status (firewalld)" "FAIL" "Firewalld не активен - ваша система подвержена сетевым атакам"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        if iptables -L | grep -q "Chain INPUT"; then
            check_security "Firewall Status (iptables)" "PASS" "Правила iptables активны и защищают вашу систему"
        else
            check_security "Firewall Status (iptables)" "FAIL" "Не найдено активных правил iptables - ваша система может быть подвержена угрозам"
        fi
    elif command -v nft >/dev/null 2>&1; then
        if nft list ruleset | grep -q "table"; then
            check_security "Firewall Status (nftables)" "PASS" "Правила nftables активны и защищают вашу систему"
        else
            check_security "Firewall Status (nftables)" "FAIL" "Не найдено активных правил nftables - ваша система может быть подвержена угрозам"
        fi
    else
        check_security "Firewall Status" "FAIL" "На этой системе не установлен признанный инструмент брандмауэра"
    fi
}
check_firewall_status

if dpkg -l | grep -q "unattended-upgrades"; then
    check_security "Unattended Upgrades" "PASS" "Автоматические обновления безопасности настроены"
else
    check_security "Unattended Upgrades" "FAIL" "Автоматические обновления безопасности не настроены - система может пропустить критические обновления"
fi


if dpkg -l | grep -q "fail2ban"; then
    if systemctl is-active fail2ban >/dev/null 2>&1; then
        check_security "Fail2ban" "PASS" "Защита от грубой силы активна и работает"
    else
        check_security "Fail2ban" "WARN" "Fail2ban установлен, но не запущен - защита от грубой силы отключена"
    fi
else
    check_security "Fail2ban" "FAIL" "Нет защиты от грубой силы - система уязвима для атак на логин"
fi

FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
if [ "$FAILED_LOGINS" -lt 10 ]; then
    check_security "Failed Logins" "PASS" "Обнаружено только $FAILED_LOGINS неудачных попыток входа - это в пределах нормального диапазона"
elif [ "$FAILED_LOGINS" -lt 50 ]; then
    check_security "Failed Logins" "WARN" "Обнаружено $FAILED_LOGINS неудачных попыток входа - это может указывать на попытки взлома"
else
    check_security "Failed Logins" "FAIL" "Обнаружено $FAILED_LOGINS неудачных попыток входа - возможно, происходит атака грубой силы"
fi
 


UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1)
if [ "$UPDATES" -eq 0 ]; then
    check_security "System Updates" "PASS" "Все системные пакеты актуальны"
else
    check_security "System Updates" "FAIL" "$UPDATES обновлений безопасности доступно - система уязвима для известных эксплойтов"
fi

SERVICES=$(systemctl list-units --type=service --state=running | grep "loaded active running" | wc -l)
if [ "$SERVICES" -lt 20 ]; then
    check_security "Running Services" "PASS" "Запущено минимальное количество сервисов ($SERVICES) - хорошо для безопасности"
elif [ "$SERVICES" -lt 40 ]; then
    check_security "Running Services" "WARN" "Запущено $SERVICES сервисов - рекомендуется уменьшить поверхность атаки"
else
    check_security "Running Services" "FAIL" "Слишком много запущенных сервисов ($SERVICES) - увеличивает поверхность атаки"
fi


if command -v netstat >/dev/null 2>&1; then
    LISTENING_PORTS=$(netstat -tuln | grep LISTEN | awk '{print $4}')
elif command -v ss >/dev/null 2>&1; then
    LISTENING_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}')
else
    check_security "Port Scanning" "FAIL" "Ни 'netstat', ни 'ss' не доступны на этой системе."
    LISTENING_PORTS=""
fi

if [ -n "$LISTENING_PORTS" ]; then
    PUBLIC_PORTS=$(echo "$LISTENING_PORTS" | awk -F':' '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
    PORT_COUNT=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
    INTERNET_PORTS=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)

    if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
        check_security "Port Security" "PASS" "Хорошая конфигурация (Всего: $PORT_COUNT, Открытых для публичного доступа: $INTERNET_PORTS порта): $PUBLIC_PORTS"
    elif [ "$PORT_COUNT" -lt 20 ] && [ "$INTERNET_PORTS" -lt 5 ]; then
        check_security "Port Security" "WARN" "Рекомендуется проверка (Всего: $PORT_COUNT, Открытых для публичного доступа: $INTERNET_PORTS порта): $PUBLIC_PORTS"
    else
        check_security "Port Security" "FAIL" "Высокий уровень воздействия (Всего: $PORT_COUNT, Открытых для публичного доступа: $INTERNET_PORTS порта): $PUBLIC_PORTS"
    fi
else
    check_security "Port Scanning" "WARN" "Не удалось выполнить сканирование портов из-за отсутствующих инструментов. Убедитесь, что установлены 'ss' или 'netstat'."
fi


format_for_report() {
    local message="$1"
    echo "$message" >> "$REPORT_FILE"
}


DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
if [ "$DISK_USAGE" -lt 50 ]; then
    check_security "Disk Usage" "PASS" "Достаточно свободного места на диске (${DISK_USAGE}% используется - Использовано: ${DISK_USED} из ${DISK_TOTAL}, Доступно: ${DISK_AVAIL})"
elif [ "$DISK_USAGE" -lt 80 ]; then
    check_security "Disk Usage" "WARN" "Использование места на диске умеренное (${DISK_USAGE}% используется - Использовано: ${DISK_USED} из ${DISK_TOTAL}, Доступно: ${DISK_AVAIL})"
else
    check_security "Disk Usage" "FAIL" "Критическое использование места на диске (${DISK_USAGE}% используется - Использовано: ${DISK_USED} из ${DISK_TOTAL}, Доступно: ${DISK_AVAIL})"
fi


MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
if [ "$MEM_USAGE" -lt 50 ]; then
    check_security "Memory Usage" "PASS" "Здоровое использование памяти (${MEM_USAGE}% используется - Использовано: ${MEM_USED} из ${MEM_TOTAL}, Доступно: ${MEM_AVAIL})"
elif [ "$MEM_USAGE" -lt 80 ]; then
    check_security "Memory Usage" "WARN" "Умеренное использование памяти (${MEM_USAGE}% используется - Использовано: ${MEM_USED} из ${MEM_TOTAL}, Доступно: ${MEM_AVAIL})"
else
    check_security "Memory Usage" "FAIL" "Критическое использование памяти (${MEM_USAGE}% используется - Использовано: ${MEM_USED} из ${MEM_TOTAL}, Доступно: ${MEM_AVAIL})"
fi


CPU_CORES=$(nproc)
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($2)}')
CPU_IDLE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($8)}')
CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
if [ "$CPU_USAGE" -lt 50 ]; then
    check_security "CPU Usage" "PASS" "Здоровое использование CPU (${CPU_USAGE}% используется - Активность: ${CPU_USAGE}%, Ожидание: ${CPU_IDLE}%, Нагрузка: ${CPU_LOAD}, Ядра: ${CPU_CORES})"
elif [ "$CPU_USAGE" -lt 80 ]; then
    check_security "CPU Usage" "WARN" "Умеренное использование CPU (${CPU_USAGE}% используется - Активность: ${CPU_USAGE}%, Ожидание: ${CPU_IDLE}%, Нагрузка: ${CPU_LOAD}, Ядра: ${CPU_CORES})"
else
    check_security "CPU Usage" "FAIL" "Критическое использование CPU (${CPU_USAGE}% используется - Активность: ${CPU_USAGE}%, Ожидание: ${CPU_IDLE}%, Нагрузка: ${CPU_LOAD}, Ядра: ${CPU_CORES})"
fi


if grep -q "^Defaults.*logfile" /etc/sudoers; then
    check_security "Sudo Logging" "PASS" "Команды Sudo записываются для целей аудита"
else
    check_security "Sudo Logging" "FAIL" "Команды Sudo не записываются - снижает возможности аудита"
fi


if [ -f "/etc/security/pwquality.conf" ]; then
    if grep -q "minlen.*12" /etc/security/pwquality.conf; then
        check_security "Password Policy" "PASS" "Строгая политика паролей соблюдается"
    else
        check_security "Password Policy" "FAIL" "Слабая политика паролей - пароли могут быть слишком простыми"
    fi
else
    check_security "Password Policy" "FAIL" "Политика паролей не настроена - система принимает слабые пароли"
fi


COMMON_SUID_PATHS='^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
KNOWN_SUID_BINS='ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

SUID_FILES=$(find / -type f -perm -4000 2>/dev/null | \
    grep -v -E "$COMMON_SUID_PATHS" | \
    grep -v -E "$KNOWN_SUID_BINS" | \
    wc -l)

if [ "$SUID_FILES" -eq 0 ]; then
    check_security "SUID Files" "PASS" "Подозрительных SUID файлов не обнаружено - хорошая практика безопасности"
else
    check_security "SUID Files" "WARN" "Обнаружено $SUID_FILES SUID файлов вне стандартных расположений - проверьте их легитимность"
fi


echo "================================" >> "$REPORT_FILE"
echo "Сводная информация о системе:" >> "$REPORT_FILE"
echo "Имя хоста: $(hostname)" >> "$REPORT_FILE"
echo "Ядро: $(uname -r)" >> "$REPORT_FILE"
echo "ОС: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" >> "$REPORT_FILE"
echo "Количество ядер CPU: $(nproc)" >> "$REPORT_FILE"
echo "Общий объем памяти: $(free -h | awk '/^Mem:/ {print $2}')" >> "$REPORT_FILE"
echo "Общий объем дискового пространства: $(df -h / | awk 'NR==2 {print $2}')" >> "$REPORT_FILE"
echo "================================" >> "$REPORT_FILE"

echo -e "\nАудит VPS завершен. Полный отчет сохранен в $REPORT_FILE"
echo -e "Ознакомьтесь с $REPORT_FILE для получения подробных рекомендаций."
echo "================================" >> "$REPORT_FILE"
echo "Конец отчета проверки VPS" >> "$REPORT_FILE"
echo "Пожалуйста, ознакомьтесь со всеми неудачными проверками и выполните рекомендованные исправления." >> "$REPORT_FILE"
