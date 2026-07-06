#include "MainWindow.hpp"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("Ghostwire");
    QApplication::setOrganizationName("Ghostwire");
    QApplication::setApplicationVersion("2.0.0");

    MainWindow window;
    window.show();

    // `ghostwire --demo` jumps straight into the built-in example attack.
    const QStringList args = QApplication::arguments();
    if (args.contains("--demo")) {
        window.openExampleAttack();
    }

    return app.exec();
}
