const express = require('express')
const router = express.Router()
const fileMulter = require('../middleware/file') //multer
const { v4: uuid } = require('uuid')

class Book {
    constructor(id = uuid(), title = "", description = "", authors = "", favorite = "", fileCover = "", fileName = "", fileBook = "", bookView = 0) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.authors = authors;
        this.favorite = favorite;
        this.fileCover = fileCover;
        this.fileName = fileName;
        this.fileBook = fileBook;
        this.bookView = bookView;
    }
}

const library = {
    books: [
        new Book(id = uuid(), 'Война и мир', 'Великая книги Льва Толстого', 'Лев Толстой', '', '', '', '', 0),
        new Book(id = uuid(), 'Евгений Онегин', 'Бессмертная классика', 'Александр Пушкин',  '', '', '', '', 0),
    ],
};

function incr(bookID) {
    return new Promise((resolve, reject) => {
        // Формирование URL для увеличения счетчика
        const url = `http://counter:4000/counter/${bookID}/incr`;

        // Выполнение POST-запроса для увеличения счетчика
        fetch(url, { method: 'POST' })
            .then(res => {
                if (res.ok) {
                    resolve(); // Успешное выполнение, разрешаем Promise
                } else {
                    reject(new Error('Ошибка при увеличении счетчика')); // Ошибка в ответе, отклоняем Promise
                }
            })
            .catch(err => {
                console.error('Ошибка сети при увеличении счетчика: ', err);
                reject(err); // Ошибка сети, отклоняем Promise
            });
    });
}

// Функция для получения текущего значения счетчика просмотров книги
function db(bookID) {
    return new Promise((resolve, reject) => {
        // Формирование URL для получения текущего значения счетчика
        const url = `http://counter:4000/counter/${bookID}`;

        // Выполнение GET-запроса для получения счетчика
        fetch(url)
            .then(res => res.json()) // Преобразование ответа в JSON
            .then(data => {
                const { books } = library;
                books[bookID].bookView = data.cnt; // Обновление значения счетчика в объекте книги
                resolve(); // Успешное выполнение, разрешаем Promise
            })
            .catch(err => {
                console.error('Ошибка при получении счетчика: ', err);
                reject(err); // Ошибка при запросе, отклоняем Promise
            });
    });
}



router.get('/', (req, res) => {
    const {books} = library;
    res.render("index", {
        title: "Библиотека",
        books: books,
    });
});


router.get('/create', (req, res) => { 
    res.render("create", {
        title: "Библиотека | Создание книги",
        books: {},
    });
});

router.post('/create', fileMulter.single('fileBook'), (req, res) => {
    const {books} = library;
    const {title, description, authors, favorite, fileCover} = req.body;

    if(req.file){
        const {path} = req.file
        const {filename} = req.file
        const newBook = new Book(id = uuid(), title, description, authors, favorite, fileCover, fileName = filename, fileBook = path, bookView = 0) 
        books.push(newBook);  
        res.redirect('/')      
    } else {
        const newBook = new Book(id = uuid(), title, description, authors, favorite, bookView = 0) 
        books.push(newBook);  
        res.redirect('/')      
    }

});



router.get('/update/:id', (req, res) => { //вносим правки в книгу
    const {books} = library;
    const {id} = req.params;
    const idx = books.findIndex(el => el.id === id);

    if (idx === -1) {
        res.redirect('/404');
    } 

    res.render("update", {
        title: "Библиотека | Редактирование книги",
        books: books[idx],
    });
});
router.post('/update/:id',  fileMulter.single('fileBook'), (req, res) => {
    const {books} = library;
    const {id} = req.params;
    const {title, description, authors, favorite, fileCover} = req.body;
    const idx = books.findIndex(el => el.id === id);
   
    if (idx === -1) {
        res.redirect('/404');
    } else {
        if(req.file){
            const {path} = req.file
            const {filename} = req.file
            books[idx] = {
                ...books[idx],
                title,
                description,
                authors,
                favorite, 
                fileCover,
                fileName: filename,
                fileBook: path,
                bookView: 0,
            };

        } else {
            books[idx] = {
                ...books[idx],
                title,
                description,
                authors,
            };

        }
    }
    res.redirect(`/${id}`);
});


router.post('/delete/:id', (req, res) => {
    const {books} = library;
    const {id} = req.params;
    const idx = books.findIndex(el => el.id === id);

    if (idx === -1) {
        res.redirect('/404');
    } 

    books.splice(idx, 1);
    res.redirect(`/`);
});


router.get('/:id', async (req, res) => {
    const { books } = library;
    const { id } = req.params;
    const idx = books.findIndex(el => el.id === id);

    if (idx === -1) {
        res.redirect('/404');
        return;
    } else {
        try {
            await db(idx); // Асинхронно получаем текущее значение счетчика и дожидаемся ответа
            await incr(idx); // Асинхронно увеличиваем счетчик и дожидаемся ответа
            res.render("view", {
                title: "Подробнее о книге",
                book: books[idx],
            });
        } catch (error) {
            console.error('Ошибка при подсчете просмотров: ', error);
            // Обрабатываем ошибку, возможно редирект на страницу ошибки или вывод сообщения
            res.status(500).send('Ошибка сервера');
        }
    }
});


router.get('/:id/download', (req, res) => { //скачиваем книгу
    const {books} = library
    const {id} = req.params
    const idx = books.findIndex(el => el.id === id)

    if( idx !== -1) {
        res.download(books[idx].fileBook)
    } else {
        res.redirect('/404');
    }
})


module.exports = router;