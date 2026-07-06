#include "MainWindow.hpp"

#include <QApplication>
#include <QFile>
#include <QStringList>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("Ghostwire");
    QApplication::setOrganizationName("Ghostwire");
    QApplication::setApplicationVersion("2.0.1");

    MainWindow window;
    window.show();

    // `ghostwire --demo` jumps straight into the built-in example attack;
    // `ghostwire path\to\events.csv` opens a CSV on launch.
    const QStringList args = QApplication::arguments();
    if (args.contains("--demo")) {
        window.openExampleAttack();
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
