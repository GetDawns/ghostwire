#include "MainWindow.hpp"

#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMessageBox>
#include <QStringList>
#include <QTextStream>

#include <exception>

namespace {

// A QApplication that refuses to die silently. If any slot or event handler
// throws a C++ exception, Qt would otherwise let it escape the event loop and
// std::terminate the process with no message — which is exactly the "it just
// closes" crash. Here we catch it, write it to a log, tell the user, and keep
// the app alive.
class SafeApplication : public QApplication {
public:
    SafeApplication(int& argc, char** argv) : QApplication(argc, argv) {}

    bool notify(QObject* receiver, QEvent* event) override {
        try {
            return QApplication::notify(receiver, event);
        } catch (const std::exception& e) {
            report(QString::fromUtf8(e.what()));
        } catch (...) {
            report(QStringLiteral("an unknown error"));
        }
        return false;
    }

private:
    void report(const QString& what) {
        const QString line =
            QDateTime::currentDateTime().toString(Qt::ISODate) + "  " + what;
        QFile log(QDir::temp().filePath("ghostwire-error.log"));
        if (log.open(QIODevice::Append | QIODevice::Text)) {
            QTextStream(&log) << line << "\n";
        }
        QMessageBox::critical(
            nullptr, "Ghostwire",
            "Something went wrong and was stopped before it could close the app:\n\n" +
                what +
                "\n\nA note was written to ghostwire-error.log in your temp folder.");
    }
};

} // namespace

int main(int argc, char* argv[]) {
    SafeApplication app(argc, argv);
    QApplication::setApplicationName("Ghostwire");
    QApplication::setOrganizationName("Ghostwire");
    QApplication::setApplicationVersion("2.0.1");

    MainWindow window;
    window.show();

    // `ghostwire --demo` jumps straight into the built-in example attack;
    // `ghostwire --scan` starts a scan on launch; `ghostwire path\to\events.csv`
    // opens a CSV.
    const QStringList args = QApplication::arguments();
    if (args.contains("--demo")) {
        window.openExampleAttack();
    } else if (args.contains("--scan")) {
        window.startScan();
    } else {
        for (int i = 1; i < args.size(); ++i) {
            if (!args[i].startsWith('-') && QFile::exists(args[i])) {
                window.openCsv(args[i]);
                break;
            }
        }
    }

    return app.exec();
}
