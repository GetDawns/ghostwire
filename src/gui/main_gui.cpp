#include "MainWindow.hpp"

#include <QApplication>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    QApplication::setApplicationName("Ghostwire");
    QApplication::setOrganizationName("Ghostwire");
    QApplication::setApplicationVersion("1.0.0");

    MainWindow window;
    window.show();

    return app.exec();
}
