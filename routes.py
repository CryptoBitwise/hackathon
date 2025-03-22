<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}{% endblock %} - Job Connector</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <header>
        <h1>Job Connector</h1>
        <nav>
            <ul>
                <li><a href="{{ url_for('index') }}">Home</a></li>
                {% if current_user.is_authenticated %}
                    <li><a href="{{ url_for('jobs') }}">Jobs</a></li>
                    <li><a href="{{ url_for('profile') }}">Profile</a></li>
                    <li><a href="{{ url_for('logout') }}">Logout</a></li>
                {% else %}
                    <li><a href="{{ url_for('login') }}">Login</a></li>
                    <li><a href="{{ url_for('register') }}">Register</a></li>
                {% endif %}
            </ul>
        </nav>
    </header>
    <main>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="flash-messages">
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
                </div>
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </main>
    <footer>
        <p>&copy; 2023 Job Connector</p>
    </footer>
</body>
</html>