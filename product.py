from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import os
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


blacklist = set()





app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:5787@localhost/e_commerce'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'SUPER_SECRET_KEY'
app.config['JWT_SECRET_KEY'] = 'ANOTHER_SUPER_SECRET_KEY'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)  
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=7) 

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

revoked_tokens = set()  # This can also be a database or Redis storage for scalability.

# Revoked token callback
@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'message': 'Token has been revoked'}), 401





class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='customer')



order_products = db.Table('order_products',
    db.Column('order_id', db.Integer, db.ForeignKey('order.id'), primary_key=True),
    db.Column('product_id', db.Integer, db.ForeignKey('product.id'), primary_key=True)
)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('products', lazy=True))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    orders = db.relationship('Order', backref='customer', lazy=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    products = db.relationship('Product', secondary=order_products, backref=db.backref('orders', lazy=True))

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.relationship('Permission', backref='role', lazy=True)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)




with app.app_context():
    db.create_all()



with app.app_context():
    if not User.query.filter_by(email="admin@example.com").first():
        hashed_password = bcrypt.generate_password_hash("securepassword").decode("utf-8")
        admin_user = User(username="AdminUser", email="admin@example.com", password=hashed_password, role="admin")
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")


@app.route('/role', methods=['POST'])
@jwt_required()
def create_role():
    data = request.get_json()
    role_name = data.get('name')

    if not role_name:
        return jsonify({'message': 'Role name is required'}), 400

    if Role.query.filter_by(name=role_name).first():
        return jsonify({'message': f'Role {role_name} already exists'}), 409

    new_role = Role(name=role_name)
    db.session.add(new_role)
    db.session.commit()

    return jsonify({'message': f'Role {role_name} created successfully'}), 201


@app.route('/permission', methods=['POST'])
@jwt_required()
def create_permission():
    data = request.get_json()
    permission_name = data.get('name')
    role_id = data.get('role_id')  # Role to which the permission will belong

    if not permission_name or not role_id:
        return jsonify({'message': 'Permission name and role_id are required'}), 400

    role = Role.query.get(role_id)
    if not role:
        return jsonify({'message': 'Role not found'}), 404

    new_permission = Permission(name=permission_name, role_id=role_id)
    db.session.add(new_permission)
    db.session.commit()

    return jsonify({'message': f'Permission {permission_name} created and assigned to role {role.name}'}), 201


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password']
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 409

    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201



@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data['email']
    password = data['password']

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


@app.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """
    This endpoint allows the user to refresh their access token using a refresh token.
    """
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': new_access_token}), 200



@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return jsonify({
        'message': f'Welcome {user.username}, you have access to this protected route.'
    })





@app.route('/admin', methods=['GET'])
@jwt_required()
def admin_route():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user.role != 'admin':
        return jsonify({'message': 'Access denied: Admins only.'}), 403

    return jsonify({'message': 'Welcome Admin! You have access to this route.'})


@app.route('/product', methods=['POST'])
@jwt_required()
def create_product():
    # Get the current user's ID from the JWT token
    current_user_id = get_jwt_identity()
    
    # Retrieve the user from the database
    user = User.query.get(current_user_id)
    
    # Check if the user has the 'admin' role
    if user.role != 'admin':
        return jsonify({'message': 'Access denied: Admins only.'}), 403

    # Proceed with product creation
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    price = data.get('price')
    category_id = data.get('category_id')

    # Check if the category exists
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'message': 'Category not found'}), 404
    
    # Create the product and add it to the database
    product = Product(name=name, description=description, price=price, category_id=category_id)
    db.session.add(product)
    db.session.commit()

    return jsonify({'message': 'Product created', 'id': product.id}), 201




@app.route('/check-admins', methods=['GET'])
def check_admins():
    admins = User.query.filter_by(role="admin").all()
    if not admins:
        return jsonify({'message': 'No admin users found.'}), 404

    admin_list = [{'id': admin.id, 'username': admin.username, 'email': admin.email} for admin in admins]
    return jsonify({'admins': admin_list}), 200



@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'id': product.id, 'name': product.name, 'price': product.price, 'category': product.category.name} for product in products])



@app.route('/category', methods=['POST'])
@jwt_required()
def create_category():
    data = request.get_json()
    name = data.get('name')

    if not name:
        return jsonify({'message': 'Name is required'}), 400
    
    existing_category = Category.query.filter_by(name=name).first()
    if existing_category:
        return jsonify({'message': 'Category already exists'}), 409

    category = Category(name=name)
    db.session.add(category)
    db.session.commit()

    return jsonify({'message': 'Category created', 'id': category.id}), 201


@app.route('/categories', methods=['GET'])
def get_categories():
    categories = Category.query.all()
    return jsonify([{'id': category.id, 'name': category.name} for category in categories])



@app.route('/customer', methods=['POST'])
@jwt_required()
def create_customer():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')

    customer = Customer(name=name, email=email)
    db.session.add(customer)
    db.session.commit()
    return jsonify({'message': 'Customer created', 'id': customer.id}), 201


@app.route('/customers', methods=['GET'])
def get_customers():
    customers = Customer.query.all()
    return jsonify([{'id': customer.id, 'name': customer.name, 'email': customer.email} for customer in customers])



@app.route('/order', methods=['POST'])
@jwt_required()
def create_order():
    data = request.get_json()
    customer_id = data.get('customer_id')
    product_ids = data.get('product_ids', [])

    customer = Customer.query.get(customer_id)
    if not customer:
        return jsonify({'message': 'Customer not found'}), 404

    order = Order(customer_id=customer_id)
    for product_id in product_ids:
        product = Product.query.get(product_id)
        if product:
            order.products.append(product)

    db.session.add(order)
    db.session.commit()
    return jsonify({'message': 'Order created', 'id': order.id}), 201


@app.route('/orders', methods=['GET'])
def get_orders():
    orders = Order.query.all()
    return jsonify([{
        'id': order.id,
        'date': order.date,
        'customer': order.customer.name,
        'products': [{'id': product.id, 'name': product.name} for product in order.products]
    } for order in orders])

@app.route('/orders/<int:id>', methods=['PUT'])
@jwt_required()
def update_order(id):
    data = request.get_json()
    order = Order.query.get(id)
    
    if not order:
        return jsonify({'message': 'Order not found'}), 404
    
    order.customer_id = data.get('customer_id', order.customer_id)
    product_ids = data.get('product_ids', [])
    
    order.products.clear()

    for product_id in product_ids:
        product = Product.query.get(product_id)
        if product:
            order.products.append(product)

    db.session.commit()

    return jsonify({'message': 'Order updated successfully'})



@app.route('/products/<int:id>', methods=['PUT'])
@jwt_required()
def update_product(id):
    data = request.get_json()
    product = Product.query.get(id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.category_id = data.get('category_id', product.category_id)
    db.session.commit()

    return jsonify({'message': 'Product updated successfully'})


@app.route('/customers/<int:id>', methods=['PUT'])
@jwt_required()
def update_customer(id):
    data = request.get_json()
    customer = Customer.query.get(id)
    if not customer:
        return jsonify({'message': 'Customer not found'}), 404
    
    customer.name = data.get('name', customer.name)
    customer.email = data.get('email', customer.email)
    db.session.commit()

    return jsonify({'message': 'Customer updated successfully'})



@app.route('/products/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_product(id):
    product = Product.query.get(id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Product deleted successfully'})


@app.route('/customers/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_customer(id):
    customer = Customer.query.get(id)
    if not customer:
        return jsonify({'message': 'Customer not found'}), 404
    
    db.session.delete(customer)
    db.session.commit()

    return jsonify({'message': 'Customer deleted successfully'})


@app.route('/orders/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_order(id):
    order = Order.query.get(id)
    if not order:
        return jsonify({'message': 'Order not found'}), 404
    
    db.session.delete(order)
    db.session.commit()

    return jsonify({'message': 'Order deleted successfully'})

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Revoke the current token by adding its JTI to the blacklist.
    """
    jti = get_jwt()["jti"]  # Get the unique identifier of the token
    blacklist.add(jti)  # Add to the blacklist
    logger.debug(f"Blacklist after logout: {blacklist}")
    return jsonify({'message': 'Successfully logged out'}), 200

@app.route('/logout-refresh', methods=['POST'])
@jwt_required(refresh=True)
def logout_refresh():
    """
    Revoke the refresh token by adding its JTI to the blacklist.
    """
    jti = get_jwt()["jti"]
    blacklist.add(jti)
    logger.debug(f"Checking JTI: {jti} | Blacklist: {blacklist}")
    return jsonify({'message': 'Refresh token successfully logged out'}), 200





if __name__ == '__main__':
    app.run(debug=True)
