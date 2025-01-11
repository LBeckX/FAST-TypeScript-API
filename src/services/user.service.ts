import {User} from "../entitites/user.entity.js";
import {databaseConfig} from "../config/database.config.js";
import * as argon2 from "argon2";

export class UserService {

    static userRepository = databaseConfig.getRepository(User)

    static async create({email, password, role = 'USER'}: Partial<User>) {
        const user = new User()
        user.email = email
        user.password = await argon2.hash(password)
        user.role = role
        return await this.userRepository.save(user)
    }

    static async update(user: User) {
        return await this.userRepository.update({id: user.id}, user)
    }

    static async getByEmail(email: string) {
        const user = await this.userRepository.findOne({where: {email}})
        if (!user) {
            throw new Error('User not found')
        }
        return user;
    }

    static async getById(id: number) {
        const user = await this.userRepository.findOne({where: {id}})
        if (!user) {
            throw new Error('User not found')
        }
        return user
    }

    static async getAll() {
        return await this.userRepository.find()
    }

    static async delete(id: number) {
        return await this.userRepository.delete({id})
    }
}