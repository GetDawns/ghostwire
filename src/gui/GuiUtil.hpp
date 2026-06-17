#pragma once

#include <QString>
#include <string>

inline QString qstr(const std::string& value) {
    return QString::fromStdString(value);
}

inline std::string stdstr(const QString& value) {
    return value.toStdString();
}
